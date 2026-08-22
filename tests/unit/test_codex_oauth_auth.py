import asyncio
import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from keyring.errors import PasswordDeleteError
from pydantic import SecretStr

from netsage.ai.providers.openai_codex import (
    CODEX_OAUTH_KEYRING_ACCOUNT,
    CODEX_OAUTH_KEYRING_SERVICE,
    CodexExistingAuthImporter,
    CodexExistingAuthImportError,
    CodexOAuthTokenBundle,
    CodexOAuthTokenManager,
    CodexOAuthTokenState,
    InMemoryCodexOAuthTokenStore,
    KeyringCodexOAuthTokenStore,
)
from netsage.ai.providers.openai_codex import auth as auth_module

REFRESH_CANARY = "oauth-refresh-canary"


def jwt(*, expires_at: datetime, account_id: str = "account-synthetic") -> str:
    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    payload = {
        "exp": int(expires_at.timestamp()),
        "https://api.openai.com/auth": {"chatgpt_account_id": account_id},
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.c2ln"


def bundle(*, now: datetime, expires_in: int = 3600) -> CodexOAuthTokenBundle:
    return CodexOAuthTokenBundle(
        access_token=SecretStr(jwt(expires_at=now + timedelta(seconds=expires_in))),
        refresh_token=SecretStr(REFRESH_CANARY),
        id_token=SecretStr(jwt(expires_at=now + timedelta(hours=1))),
        obtained_at=now,
    )


def test_oauth_tokens_use_one_separate_keyring_bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values: dict[tuple[str, str], str] = {}
    writes: list[tuple[str, str]] = []
    monkeypatch.setattr(
        auth_module.keyring,
        "get_keyring",
        lambda: type("Backend", (), {"priority": 1})(),
    )

    def save(service: str, account: str, value: str) -> None:
        writes.append((service, account))
        values[(service, account)] = value

    monkeypatch.setattr(auth_module.keyring, "set_password", save)
    monkeypatch.setattr(
        auth_module.keyring,
        "get_password",
        lambda service, account: values.get((service, account)),
    )

    def delete(service: str, account: str) -> None:
        try:
            del values[(service, account)]
        except KeyError as error:
            raise PasswordDeleteError("missing") from error

    monkeypatch.setattr(auth_module.keyring, "delete_password", delete)
    generation = "a" * 32
    store = KeyringCodexOAuthTokenStore(generation_factory=lambda: generation)
    tokens = bundle(now=datetime(2026, 8, 22, tzinfo=UTC))

    store.save(tokens)
    loaded = store.load()

    assert writes[-1] == (CODEX_OAUTH_KEYRING_SERVICE, CODEX_OAUTH_KEYRING_ACCOUNT)
    assert any(generation in account for _service, account in writes[:-1])
    assert CODEX_OAUTH_KEYRING_SERVICE == "NetSage AI OpenAI Codex"
    assert ("NetSage", CODEX_OAUTH_KEYRING_ACCOUNT) not in values
    assert loaded.access_token.get_secret_value() == tokens.access_token.get_secret_value()
    assert tokens.access_token.get_secret_value() not in repr(loaded)
    store.delete()
    assert store.configured() is False


def test_failed_chunked_update_keeps_previous_generation_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        auth_module.keyring,
        "get_keyring",
        lambda: type("Backend", (), {"priority": 1})(),
    )
    monkeypatch.setattr(
        auth_module.keyring,
        "get_password",
        lambda service, account: values.get((service, account)),
    )
    monkeypatch.setattr(
        auth_module.keyring,
        "delete_password",
        lambda service, account: values.pop((service, account), None),
    )
    monkeypatch.setattr(
        auth_module.keyring,
        "set_password",
        lambda service, account, value: values.__setitem__((service, account), value),
    )
    now = datetime(2026, 8, 22, tzinfo=UTC)
    old_tokens = bundle(now=now)
    old_store = KeyringCodexOAuthTokenStore(generation_factory=lambda: "a" * 32)
    old_store.save(old_tokens)
    monkeypatch.setattr(auth_module, "_KEYRING_CHUNK_CHARACTERS", 50)

    def fail_second_chunk(service: str, account: str, value: str) -> None:
        if account.endswith(":1") and ("b" * 32) in account:
            raise RuntimeError("synthetic keyring failure")
        values[(service, account)] = value

    monkeypatch.setattr(auth_module.keyring, "set_password", fail_second_chunk)
    new_store = KeyringCodexOAuthTokenStore(generation_factory=lambda: "b" * 32)

    with pytest.raises(auth_module.CodexOAuthCredentialStoreError):
        new_store.save(old_tokens.model_copy(update={"refresh_token": SecretStr("new-refresh")}))

    loaded = old_store.load()
    assert loaded.refresh_token.get_secret_value() == REFRESH_CANARY


@pytest.mark.asyncio
async def test_refresh_lock_prevents_parallel_refresh_token_reuse() -> None:
    now = datetime(2026, 8, 22, tzinfo=UTC)
    store = InMemoryCodexOAuthTokenStore(bundle(now=now, expires_in=1))

    class RefreshClient:
        def __init__(self) -> None:
            self.calls = 0

        async def refresh_tokens(
            self,
            tokens: CodexOAuthTokenBundle,
        ) -> CodexOAuthTokenBundle:
            self.calls += 1
            await asyncio.sleep(0)
            return tokens.model_copy(
                update={
                    "access_token": SecretStr(jwt(expires_at=now + timedelta(hours=2))),
                    "refresh_token": SecretStr("rotated-refresh-canary"),
                    "obtained_at": now,
                }
            )

    refresh = RefreshClient()
    manager = CodexOAuthTokenManager(
        store=store,
        refresh_client=refresh,
        clock=lambda: now,
    )

    first, second = await asyncio.gather(manager.valid_tokens(), manager.valid_tokens())

    assert refresh.calls == 1
    assert first.refresh_token.get_secret_value() == "rotated-refresh-canary"
    assert second.refresh_token.get_secret_value() == "rotated-refresh-canary"


def test_status_distinguishes_valid_refresh_required_expired_and_invalid() -> None:
    now = datetime(2026, 8, 22, tzinfo=UTC)

    class NeverRefresh:
        async def refresh_tokens(self, tokens: CodexOAuthTokenBundle) -> CodexOAuthTokenBundle:
            return tokens

    def state(expires_in: int) -> CodexOAuthTokenState:
        return (
            CodexOAuthTokenManager(
                store=InMemoryCodexOAuthTokenStore(bundle(now=now, expires_in=expires_in)),
                refresh_client=NeverRefresh(),
                clock=lambda: now,
            )
            .status()
            .token_state
        )

    assert state(3600) is CodexOAuthTokenState.VALID
    assert state(60) is CodexOAuthTokenState.REFRESH_REQUIRED
    assert state(-1) is CodexOAuthTokenState.EXPIRED
    malformed = bundle(now=now).model_copy(update={"access_token": SecretStr("not-a-jwt")})
    invalid = CodexOAuthTokenManager(
        store=InMemoryCodexOAuthTokenStore(malformed),
        refresh_client=NeverRefresh(),
        clock=lambda: now,
    ).status()
    assert invalid.token_state is CodexOAuthTokenState.INVALID
    assert invalid.authenticated is False


def test_existing_codex_import_is_explicit_read_only_and_keyring_only(tmp_path: Path) -> None:
    now = datetime(2026, 8, 22, tzinfo=UTC)
    source = tmp_path / "auth.json"
    source.write_text(
        json.dumps(
            {
                "tokens": {
                    "access_token": jwt(expires_at=now + timedelta(hours=1)),
                    "refresh_token": REFRESH_CANARY,
                    "id_token": jwt(expires_at=now + timedelta(hours=1)),
                    "account_id": "account-synthetic",
                },
                "last_refresh": now.isoformat(),
            }
        ),
        encoding="utf-8",
    )
    before = source.read_bytes()
    store = InMemoryCodexOAuthTokenStore()
    importer = CodexExistingAuthImporter(store)

    assert importer.detected(source) is True
    imported = importer.import_file(source)

    assert source.read_bytes() == before
    assert imported.account_id == "account-synthetic"
    assert store.configured() is True
    assert not tuple(tmp_path.glob("*.tmp"))


def test_existing_codex_import_absent_and_malformed_are_bounded(tmp_path: Path) -> None:
    importer = CodexExistingAuthImporter(InMemoryCodexOAuthTokenStore())
    missing = tmp_path / "missing.json"
    malformed = tmp_path / "auth.json"
    malformed.write_text('{"tokens":{"access_token":"secret-canary"}}', encoding="utf-8")

    assert importer.detected(missing) is False
    with pytest.raises(CodexExistingAuthImportError):
        importer.import_file(missing)
    with pytest.raises(CodexExistingAuthImportError) as caught:
        importer.import_file(malformed)
    assert "secret-canary" not in str(caught.value)
