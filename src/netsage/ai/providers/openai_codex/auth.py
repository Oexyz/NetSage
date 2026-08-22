"""OS-keyring-only Codex OAuth storage and refresh serialization."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Protocol
from uuid import uuid4

import keyring
from keyring.errors import PasswordDeleteError

from netsage.ai.providers.openai_codex.models import (
    CodexOAuthStatus,
    CodexOAuthTokenBundle,
    CodexOAuthTokenState,
)
from netsage.ai.providers.openai_codex.protocol import CODEX_OAUTH_REFRESH_SKEW_SECONDS

CODEX_OAUTH_KEYRING_SERVICE = "NetSage AI OpenAI Codex"
CODEX_OAUTH_KEYRING_ACCOUNT = "oauth-token-bundle-v1"
CODEX_OAUTH_KEYRING_CHUNK_PREFIX = "oauth-token-bundle-v1:"
_KEYRING_CHUNK_CHARACTERS = 1000
_MAX_KEYRING_CHUNKS = 64


class CodexOAuthCredentialStoreError(RuntimeError):
    """Bounded storage failure which never includes keyring data."""


class CodexOAuthNotAuthenticatedError(CodexOAuthCredentialStoreError):
    pass


class CodexOAuthTokenStore(Protocol):
    def save(self, tokens: CodexOAuthTokenBundle) -> None: ...

    def load(self) -> CodexOAuthTokenBundle: ...

    def delete(self, *, missing_ok: bool = False) -> None: ...

    def configured(self) -> bool: ...


class CodexOAuthRefreshClient(Protocol):
    async def refresh_tokens(self, tokens: CodexOAuthTokenBundle) -> CodexOAuthTokenBundle: ...


class KeyringCodexOAuthTokenStore(CodexOAuthTokenStore):
    """Atomically activate a complete, size-safe bundle of keyring chunks."""

    def __init__(self, *, generation_factory: Callable[[], str] | None = None) -> None:
        self._generation_factory = generation_factory or (lambda: uuid4().hex)

    @staticmethod
    def ensure_available() -> None:
        try:
            backend = keyring.get_keyring()
            priority = backend.priority
        except Exception as error:
            raise CodexOAuthCredentialStoreError(
                "Secure OS credential storage is unavailable"
            ) from error
        if priority <= 0:
            raise CodexOAuthCredentialStoreError("Secure OS credential storage is unavailable")

    def save(self, tokens: CodexOAuthTokenBundle) -> None:
        self.ensure_available()
        serialized = tokens.to_keyring_value()
        chunks = tuple(
            serialized[offset : offset + _KEYRING_CHUNK_CHARACTERS]
            for offset in range(0, len(serialized), _KEYRING_CHUNK_CHARACTERS)
        )
        if not chunks or len(chunks) > _MAX_KEYRING_CHUNKS:
            raise CodexOAuthCredentialStoreError("Codex OAuth credential bundle is too large")
        generation = self._generation_factory()
        if not _valid_generation(generation):
            raise CodexOAuthCredentialStoreError("Codex OAuth keyring generation is invalid")
        previous = self._read_pointer()
        previous_manifest = _parse_manifest(previous) if previous is not None else None
        written_accounts: list[str] = []
        try:
            for index, chunk in enumerate(chunks):
                account = _chunk_account(generation, index)
                keyring.set_password(CODEX_OAUTH_KEYRING_SERVICE, account, chunk)
                written_accounts.append(account)
            pointer = json.dumps(
                {
                    "schema_version": 2,
                    "generation": generation,
                    "chunk_count": len(chunks),
                },
                separators=(",", ":"),
            )
            # The small active pointer is switched only after every secret chunk exists.
            keyring.set_password(
                CODEX_OAUTH_KEYRING_SERVICE,
                CODEX_OAUTH_KEYRING_ACCOUNT,
                pointer,
            )
        except Exception as error:
            for account in written_accounts:
                self._delete_account(account, missing_ok=True, suppress_errors=True)
            raise CodexOAuthCredentialStoreError(
                "Unable to store Codex OAuth credentials securely"
            ) from error
        if previous_manifest is not None and previous_manifest[0] != generation:
            for index in range(previous_manifest[1]):
                self._delete_account(
                    _chunk_account(previous_manifest[0], index),
                    missing_ok=True,
                    suppress_errors=True,
                )

    def load(self) -> CodexOAuthTokenBundle:
        self.ensure_available()
        value = self._read_pointer()
        if value is None:
            raise CodexOAuthNotAuthenticatedError("Codex OAuth is not authenticated")
        try:
            # Read schema 1 directly for forward migration from early development builds.
            try:
                return CodexOAuthTokenBundle.from_keyring_value(value)
            except ValueError:
                generation, chunk_count = _required_manifest(value)
            chunks = [
                self._read_chunk(_chunk_account(generation, index)) for index in range(chunk_count)
            ]
            return CodexOAuthTokenBundle.from_keyring_value("".join(chunks))
        except ValueError as error:
            raise CodexOAuthCredentialStoreError(
                "Stored Codex OAuth credentials are invalid"
            ) from error

    def delete(self, *, missing_ok: bool = False) -> None:
        self.ensure_available()
        pointer = self._read_pointer()
        if pointer is None:
            if missing_ok:
                return
            raise CodexOAuthNotAuthenticatedError("Codex OAuth is not authenticated")
        manifest = _parse_manifest(pointer)
        if manifest is not None:
            try:
                for index in range(manifest[1]):
                    self._delete_account(
                        _chunk_account(manifest[0], index),
                        missing_ok=False,
                        suppress_errors=False,
                    )
            except Exception as error:
                raise CodexOAuthCredentialStoreError(
                    "Unable to remove Codex OAuth credentials"
                ) from error
        self._delete_account(
            CODEX_OAUTH_KEYRING_ACCOUNT,
            missing_ok=missing_ok,
            suppress_errors=False,
        )

    def configured(self) -> bool:
        try:
            self.load()
        except CodexOAuthNotAuthenticatedError:
            return False
        return True

    def _read_pointer(self) -> str | None:
        try:
            return keyring.get_password(
                CODEX_OAUTH_KEYRING_SERVICE,
                CODEX_OAUTH_KEYRING_ACCOUNT,
            )
        except Exception as error:
            raise CodexOAuthCredentialStoreError(
                "Unable to read Codex OAuth credentials securely"
            ) from error

    @staticmethod
    def _read_chunk(account: str) -> str:
        try:
            value = keyring.get_password(CODEX_OAUTH_KEYRING_SERVICE, account)
        except Exception as error:
            raise CodexOAuthCredentialStoreError(
                "Unable to read Codex OAuth credentials securely"
            ) from error
        if value is None:
            raise ValueError("missing keyring chunk")
        return value

    @staticmethod
    def _delete_account(
        account: str,
        *,
        missing_ok: bool,
        suppress_errors: bool,
    ) -> None:
        try:
            keyring.delete_password(CODEX_OAUTH_KEYRING_SERVICE, account)
        except PasswordDeleteError:
            if not missing_ok and not suppress_errors:
                raise
        except Exception:
            if not suppress_errors:
                raise


def _chunk_account(generation: str, index: int) -> str:
    return f"{CODEX_OAUTH_KEYRING_CHUNK_PREFIX}{generation}:{index}"


def _valid_generation(value: str) -> bool:
    return len(value) == 32 and all(character in "0123456789abcdef" for character in value)


def _parse_manifest(value: str) -> tuple[str, int] | None:
    try:
        payload = json.loads(value)
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("schema_version") != 2:
        return None
    generation = payload.get("generation")
    chunk_count = payload.get("chunk_count")
    if (
        not isinstance(generation, str)
        or not _valid_generation(generation)
        or not isinstance(chunk_count, int)
        or isinstance(chunk_count, bool)
        or not 1 <= chunk_count <= _MAX_KEYRING_CHUNKS
    ):
        return None
    return generation, chunk_count


def _required_manifest(value: str) -> tuple[str, int]:
    manifest = _parse_manifest(value)
    if manifest is None:
        raise ValueError("invalid keyring manifest")
    return manifest


class InMemoryCodexOAuthTokenStore(CodexOAuthTokenStore):
    """Test-only store; production composition always uses the OS keyring."""

    def __init__(self, tokens: CodexOAuthTokenBundle | None = None) -> None:
        self._tokens = tokens

    def save(self, tokens: CodexOAuthTokenBundle) -> None:
        self._tokens = tokens

    def load(self) -> CodexOAuthTokenBundle:
        if self._tokens is None:
            raise CodexOAuthNotAuthenticatedError("Codex OAuth is not authenticated")
        return self._tokens

    def delete(self, *, missing_ok: bool = False) -> None:
        if self._tokens is None and not missing_ok:
            raise CodexOAuthNotAuthenticatedError("Codex OAuth is not authenticated")
        self._tokens = None

    def configured(self) -> bool:
        return self._tokens is not None


class CodexOAuthTokenManager:
    """Serialize refreshes per auth context and replace one complete keyring bundle."""

    def __init__(
        self,
        *,
        store: CodexOAuthTokenStore,
        refresh_client: CodexOAuthRefreshClient,
        clock: Callable[[], datetime] | None = None,
        refresh_skew_seconds: int = CODEX_OAUTH_REFRESH_SKEW_SECONDS,
    ) -> None:
        self._store = store
        self._refresh_client = refresh_client
        self._clock = clock or (lambda: datetime.now(UTC))
        self._refresh_skew = timedelta(seconds=refresh_skew_seconds)
        self._refresh_lock = asyncio.Lock()

    @property
    def configured(self) -> bool:
        return self._store.configured()

    def status(self) -> CodexOAuthStatus:
        try:
            tokens = self._store.load()
        except CodexOAuthNotAuthenticatedError:
            return CodexOAuthStatus(
                configured=False,
                authenticated=False,
                token_state=CodexOAuthTokenState.NOT_CONFIGURED,
            )
        expires_at = tokens.expires_at
        now = self._now()
        if expires_at is None or tokens.account_id is None:
            state = CodexOAuthTokenState.INVALID
            authenticated = False
        elif expires_at <= now:
            state = CodexOAuthTokenState.EXPIRED
            authenticated = False
        elif expires_at <= now + self._refresh_skew:
            state = CodexOAuthTokenState.REFRESH_REQUIRED
            authenticated = True
        else:
            state = CodexOAuthTokenState.VALID
            authenticated = True
        return CodexOAuthStatus(
            configured=True,
            authenticated=authenticated,
            token_state=state,
            expires_at=expires_at,
            plan_type=tokens.plan_type,
            auth_mode="chatgpt_oauth",
        )

    async def valid_tokens(self) -> CodexOAuthTokenBundle:
        async with self._refresh_lock:
            tokens = self._store.load()
            expires_at = tokens.expires_at
            if expires_at is None or tokens.account_id is None:
                raise CodexOAuthCredentialStoreError("Stored Codex OAuth credentials are invalid")
            if expires_at > self._now() + self._refresh_skew:
                return tokens
            refreshed = await self._refresh_client.refresh_tokens(tokens)
            if refreshed.expires_at is None or refreshed.account_id is None:
                raise CodexOAuthCredentialStoreError(
                    "Refreshed Codex OAuth credentials are invalid"
                )
            self._store.save(refreshed)
            return refreshed

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
