"""Explicit, read-only import of a compatible Codex CLI auth.json token bundle."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import JsonValue, SecretStr, TypeAdapter

from netsage.ai.providers.openai_codex.auth import CodexOAuthTokenStore
from netsage.ai.providers.openai_codex.models import CodexOAuthTokenBundle

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])
_MAX_AUTH_FILE_BYTES = 2_000_000


class CodexExistingAuthImportError(RuntimeError):
    """Safe import failure without source content, paths, or token values."""


def default_codex_auth_path() -> Path:
    codex_home = os.environ.get("CODEX_HOME")
    root = Path(codex_home) if codex_home else Path.home() / ".codex"
    return root.expanduser().resolve() / "auth.json"


class CodexExistingAuthImporter:
    def __init__(self, store: CodexOAuthTokenStore) -> None:
        self._store = store

    def detected(self, path: Path | None = None) -> bool:
        """Check only file presence; do not read credential content."""

        return (path or default_codex_auth_path()).is_file()

    def import_file(self, path: Path | None = None) -> CodexOAuthTokenBundle:
        source = path or default_codex_auth_path()
        try:
            if not source.is_file() or source.stat().st_size > _MAX_AUTH_FILE_BYTES:
                raise CodexExistingAuthImportError("Compatible Codex authentication not found.")
            payload = _JSON_OBJECT.validate_python(json.loads(source.read_bytes()))
            tokens_value = payload.get("tokens")
            if not isinstance(tokens_value, dict):
                raise ValueError("missing tokens")
            tokens = _JSON_OBJECT.validate_python(tokens_value)
            access_token = _required(tokens, "access_token")
            refresh_token = _required(tokens, "refresh_token")
            id_token = _required(tokens, "id_token")
            account_id = _optional(tokens, "account_id")
            last_refresh = payload.get("last_refresh")
            obtained_at = (
                datetime.fromisoformat(last_refresh.replace("Z", "+00:00"))
                if isinstance(last_refresh, str)
                else datetime.now(UTC)
            )
            bundle = CodexOAuthTokenBundle(
                access_token=SecretStr(access_token),
                refresh_token=SecretStr(refresh_token),
                id_token=SecretStr(id_token),
                obtained_at=obtained_at,
                imported_account_id=account_id,
            )
            if bundle.account_id is None:
                raise ValueError("missing account identifier")
            self._store.save(bundle)
            return bundle
        except CodexExistingAuthImportError:
            raise
        except Exception as error:
            raise CodexExistingAuthImportError(
                "Compatible Codex authentication could not be imported."
            ) from error


def _required(data: dict[str, JsonValue], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing {key}")
    return value


def _optional(data: dict[str, JsonValue], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError(f"invalid {key}")
    return value
