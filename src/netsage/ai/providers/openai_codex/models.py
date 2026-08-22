"""Typed secret and non-secret models for native Codex OAuth compatibility."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, SecretStr, TypeAdapter

_JSON_OBJECT = TypeAdapter(dict[str, JsonValue])
_MAX_TOKEN_BYTES = 1_000_000


class CodexOAuthErrorCode(StrEnum):
    NOT_AUTHENTICATED = "CODEX_OAUTH_NOT_AUTHENTICATED"
    CREDENTIAL_STORE_ERROR = "CODEX_OAUTH_CREDENTIAL_STORE_ERROR"
    LOGIN_UNAVAILABLE = "CODEX_OAUTH_LOGIN_UNAVAILABLE"
    LOGIN_EXPIRED = "CODEX_OAUTH_LOGIN_EXPIRED"
    ACCESS_DENIED = "CODEX_OAUTH_ACCESS_DENIED"
    RESPONSE_INVALID = "CODEX_OAUTH_RESPONSE_INVALID"
    REFRESH_FAILED = "CODEX_OAUTH_REFRESH_FAILED"
    AUTHENTICATION_EXPIRED = "CODEX_OAUTH_AUTHENTICATION_EXPIRED"
    INFERENCE_UNAVAILABLE = "CODEX_OAUTH_INFERENCE_UNAVAILABLE"
    TIMEOUT = "CODEX_OAUTH_TIMEOUT"
    OUTPUT_INVALID = "CODEX_OAUTH_OUTPUT_INVALID"
    MODEL_UNAVAILABLE = "CODEX_OAUTH_MODEL_UNAVAILABLE"
    RATE_LIMITED = "CODEX_OAUTH_RATE_LIMITED"


class CodexOAuthTokenState(StrEnum):
    NOT_CONFIGURED = "not_configured"
    VALID = "valid"
    REFRESH_REQUIRED = "refresh_required"
    EXPIRED = "expired"
    INVALID = "invalid"


class CodexOAuthTokenBundle(BaseModel):
    """One logical keyring value; repr/model dumps never reveal token strings."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    access_token: SecretStr
    refresh_token: SecretStr
    id_token: SecretStr
    obtained_at: datetime
    imported_account_id: str | None = Field(default=None, min_length=1, max_length=200)

    def to_keyring_value(self) -> str:
        return json.dumps(
            {
                "schema_version": 1,
                "access_token": self.access_token.get_secret_value(),
                "refresh_token": self.refresh_token.get_secret_value(),
                "id_token": self.id_token.get_secret_value(),
                "obtained_at": self.obtained_at.astimezone(UTC).isoformat(),
                "imported_account_id": self.imported_account_id,
            },
            separators=(",", ":"),
        )

    @classmethod
    def from_keyring_value(cls, value: str) -> Self:
        try:
            data = _JSON_OBJECT.validate_python(json.loads(value))
            if data.get("schema_version") != 1:
                raise ValueError("unsupported token bundle schema")
            return cls(
                access_token=SecretStr(_required_string(data, "access_token")),
                refresh_token=SecretStr(_required_string(data, "refresh_token")),
                id_token=SecretStr(_required_string(data, "id_token")),
                obtained_at=datetime.fromisoformat(_required_string(data, "obtained_at")),
                imported_account_id=_optional_string(data, "imported_account_id"),
            )
        except Exception as error:
            raise ValueError("stored Codex OAuth credentials are invalid") from error

    @property
    def expires_at(self) -> datetime | None:
        return jwt_expiration(self.access_token)

    @property
    def account_id(self) -> str | None:
        for token in (self.id_token, self.access_token):
            claims = jwt_claims(token)
            auth = claims.get("https://api.openai.com/auth")
            if isinstance(auth, dict):
                value = auth.get("chatgpt_account_id")
                if isinstance(value, str) and 0 < len(value) <= 200:
                    return value
        return self.imported_account_id

    @property
    def plan_type(self) -> str | None:
        claims = jwt_claims(self.id_token)
        auth = claims.get("https://api.openai.com/auth")
        if isinstance(auth, dict):
            value = auth.get("chatgpt_plan_type")
            if isinstance(value, str) and 0 < len(value) <= 100:
                return value
        return None


class CodexDeviceAuthorization(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    verification_url: str = Field(min_length=1, max_length=500)
    user_code: SecretStr
    device_auth_id: SecretStr
    interval_seconds: int = Field(ge=1, le=60)
    expires_at: datetime


class CodexOAuthStatus(BaseModel):
    """Secret-free status safe for CLI, doctor, and documentation tests."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    configured: bool
    authenticated: bool
    token_state: CodexOAuthTokenState
    expires_at: datetime | None = None
    plan_type: str | None = Field(default=None, min_length=1, max_length=100)
    auth_mode: str | None = None
    experimental: bool = True


def jwt_claims(token: SecretStr) -> dict[str, JsonValue]:
    """Decode trusted-TLS token metadata without treating claims as authorization."""

    value = token.get_secret_value()
    if len(value.encode("utf-8")) > _MAX_TOKEN_BYTES:
        return {}
    parts = value.split(".")
    if len(parts) != 3 or not all(parts):
        return {}
    payload = parts[1]
    try:
        padding = "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return _JSON_OBJECT.validate_python(json.loads(decoded))
    except Exception:
        return {}


def jwt_expiration(token: SecretStr) -> datetime | None:
    value = jwt_claims(token).get("exp")
    if not isinstance(value, int | float) or isinstance(value, bool):
        return None
    try:
        return datetime.fromtimestamp(float(value), tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _required_string(data: dict[str, JsonValue], key: str) -> str:
    value = data.get(key)
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > _MAX_TOKEN_BYTES:
        raise ValueError(f"invalid {key}")
    return value


def _optional_string(data: dict[str, JsonValue], key: str) -> str | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 200:
        raise ValueError(f"invalid {key}")
    return value
