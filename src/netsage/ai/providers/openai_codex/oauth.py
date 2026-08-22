"""Bounded native Codex device authorization and refresh HTTP client."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime

import httpx
from pydantic import BaseModel, ConfigDict, SecretStr, ValidationError, field_validator

from netsage.ai.providers.openai_codex.models import (
    CodexDeviceAuthorization,
    CodexOAuthErrorCode,
    CodexOAuthTokenBundle,
)
from netsage.ai.providers.openai_codex.protocol import (
    CODEX_DEVICE_AUTH_DEFAULT_EXPIRY_SECONDS,
    CODEX_DEVICE_AUTH_DEFAULT_INTERVAL_SECONDS,
    CODEX_DEVICE_AUTH_SLOW_DOWN_SECONDS,
    CODEX_DEVICE_REDIRECT_PATH,
    CODEX_DEVICE_TOKEN_PATH,
    CODEX_DEVICE_USER_CODE_PATH,
    CODEX_DEVICE_VERIFICATION_PATH,
    CODEX_OAUTH_CLIENT_ID,
    CODEX_OAUTH_ISSUER,
    CODEX_OAUTH_TOKEN_PATH,
)

_MAX_AUTH_RESPONSE_BYTES = 64 * 1024


class CodexOAuthProtocolError(RuntimeError):
    def __init__(
        self,
        code: CodexOAuthErrorCode,
        message: str,
        *,
        reauthentication_required: bool = False,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.reauthentication_required = reauthentication_required


class _DeviceCodeResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    device_auth_id: str
    user_code: str
    interval: int = CODEX_DEVICE_AUTH_DEFAULT_INTERVAL_SECONDS
    expires_in: int = CODEX_DEVICE_AUTH_DEFAULT_EXPIRY_SECONDS

    @field_validator("interval", "expires_in", mode="before")
    @classmethod
    def parse_integer(cls, value: object) -> object:
        if isinstance(value, str):
            return int(value)
        return value


class _AuthorizationResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    authorization_code: SecretStr
    code_verifier: SecretStr


class _TokenResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")

    access_token: SecretStr
    refresh_token: SecretStr | None = None
    id_token: SecretStr | None = None


class CodexOAuthHTTPClient:
    """Implement the compatibility protocol without Codex CLI or plaintext state."""

    def __init__(
        self,
        *,
        issuer: str = CODEX_OAUTH_ISSUER,
        transport: httpx.AsyncBaseTransport | None = None,
        request_timeout: float = 20.0,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        clock: Callable[[], datetime] | None = None,
        max_transient_attempts: int = 3,
    ) -> None:
        self._issuer = issuer.rstrip("/")
        self._transport = transport
        self._timeout = httpx.Timeout(
            timeout=request_timeout,
            connect=min(request_timeout, 10.0),
        )
        self._sleep = sleep
        self._clock = clock or (lambda: datetime.now(UTC))
        self._max_transient_attempts = max(1, min(max_transient_attempts, 4))

    async def request_device_authorization(self) -> CodexDeviceAuthorization:
        response: httpx.Response | None = None
        async with self._client() as client:
            for attempt in range(self._max_transient_attempts):
                try:
                    response = await client.post(
                        CODEX_DEVICE_USER_CODE_PATH,
                        json={"client_id": CODEX_OAUTH_CLIENT_ID},
                    )
                except httpx.TimeoutException as error:
                    if attempt + 1 >= self._max_transient_attempts:
                        raise CodexOAuthProtocolError(
                            CodexOAuthErrorCode.TIMEOUT,
                            "Codex OAuth login request timed out.",
                        ) from error
                    await self._sleep(float(2**attempt))
                    continue
                except httpx.HTTPError as error:
                    raise CodexOAuthProtocolError(
                        CodexOAuthErrorCode.LOGIN_UNAVAILABLE,
                        "Codex OAuth login is currently unavailable.",
                    ) from error
                if response.status_code not in {429, 502, 503, 504}:
                    break
                if attempt + 1 >= self._max_transient_attempts:
                    break
                await self._sleep(_retry_delay(response, attempt))

        if response is None or response.status_code != 200:
            code = (
                CodexOAuthErrorCode.RATE_LIMITED
                if response is not None and response.status_code == 429
                else CodexOAuthErrorCode.LOGIN_UNAVAILABLE
            )
            raise CodexOAuthProtocolError(code, "Codex OAuth login is currently unavailable.")
        data = _validated_json(response, _DeviceCodeResponse)
        if not data.device_auth_id or not data.user_code:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.RESPONSE_INVALID,
                "Codex OAuth returned an invalid device authorization response.",
            )
        interval = max(1, min(data.interval, 60))
        expires_in = max(1, min(data.expires_in, CODEX_DEVICE_AUTH_DEFAULT_EXPIRY_SECONDS))
        return CodexDeviceAuthorization(
            verification_url=f"{self._issuer}{CODEX_DEVICE_VERIFICATION_PATH}",
            user_code=SecretStr(data.user_code),
            device_auth_id=SecretStr(data.device_auth_id),
            interval_seconds=interval,
            expires_at=self._now() + timedelta(seconds=expires_in),
        )

    async def complete_device_authorization(
        self,
        authorization: CodexDeviceAuthorization,
    ) -> CodexOAuthTokenBundle:
        interval = authorization.interval_seconds
        async with self._client() as client:
            while self._now() < authorization.expires_at:
                await self._sleep(float(interval))
                try:
                    response = await client.post(
                        CODEX_DEVICE_TOKEN_PATH,
                        json={
                            "device_auth_id": authorization.device_auth_id.get_secret_value(),
                            "user_code": authorization.user_code.get_secret_value(),
                        },
                    )
                except httpx.TimeoutException:
                    continue
                except httpx.HTTPError as error:
                    raise CodexOAuthProtocolError(
                        CodexOAuthErrorCode.LOGIN_UNAVAILABLE,
                        "Codex OAuth authorization polling failed.",
                    ) from error
                error_code = _oauth_error_code(response)
                if response.status_code == 200:
                    code = _validated_json(response, _AuthorizationResponse)
                    return await self._exchange_authorization_code(client, code)
                if error_code == "slow_down" or response.status_code == 429:
                    interval = min(60, interval + CODEX_DEVICE_AUTH_SLOW_DOWN_SECONDS)
                    continue
                if error_code == "access_denied":
                    raise CodexOAuthProtocolError(
                        CodexOAuthErrorCode.ACCESS_DENIED,
                        "Codex OAuth authorization was denied.",
                    )
                if error_code in {"expired_token", "expired_code"}:
                    raise CodexOAuthProtocolError(
                        CodexOAuthErrorCode.LOGIN_EXPIRED,
                        "Codex OAuth device authorization expired.",
                    )
                if response.status_code in {403, 404} or error_code == "authorization_pending":
                    continue
                raise CodexOAuthProtocolError(
                    CodexOAuthErrorCode.LOGIN_UNAVAILABLE,
                    "Codex OAuth authorization polling failed.",
                )
        raise CodexOAuthProtocolError(
            CodexOAuthErrorCode.LOGIN_EXPIRED,
            "Codex OAuth device authorization expired.",
        )

    async def refresh_tokens(
        self,
        tokens: CodexOAuthTokenBundle,
    ) -> CodexOAuthTokenBundle:
        async with self._client() as client:
            try:
                response = await client.post(
                    CODEX_OAUTH_TOKEN_PATH,
                    json={
                        "client_id": CODEX_OAUTH_CLIENT_ID,
                        "grant_type": "refresh_token",
                        "refresh_token": tokens.refresh_token.get_secret_value(),
                    },
                )
            except httpx.TimeoutException as error:
                raise CodexOAuthProtocolError(
                    CodexOAuthErrorCode.TIMEOUT,
                    "Codex OAuth token refresh timed out.",
                ) from error
            except httpx.HTTPError as error:
                raise CodexOAuthProtocolError(
                    CodexOAuthErrorCode.REFRESH_FAILED,
                    "Codex OAuth token refresh failed.",
                ) from error
        if response.status_code != 200:
            error_code = _oauth_error_code(response)
            reauthenticate = response.status_code in {400, 401, 403} or error_code in {
                "invalid_grant",
                "invalid_token",
                "refresh_token_expired",
                "refresh_token_invalidated",
                "refresh_token_reused",
            }
            raise CodexOAuthProtocolError(
                (
                    CodexOAuthErrorCode.AUTHENTICATION_EXPIRED
                    if reauthenticate
                    else CodexOAuthErrorCode.REFRESH_FAILED
                ),
                (
                    "Codex authentication expired. Run: netsage ai codex login"
                    if reauthenticate
                    else "Codex OAuth token refresh failed."
                ),
                reauthentication_required=reauthenticate,
            )
        refreshed = _validated_json(response, _TokenResponse)
        access_token = refreshed.access_token.get_secret_value()
        if not access_token:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.RESPONSE_INVALID,
                "Codex OAuth token refresh returned an invalid response.",
                reauthentication_required=True,
            )
        return CodexOAuthTokenBundle(
            access_token=refreshed.access_token,
            refresh_token=refreshed.refresh_token or tokens.refresh_token,
            id_token=refreshed.id_token or tokens.id_token,
            obtained_at=self._now(),
            imported_account_id=tokens.imported_account_id,
        )

    async def _exchange_authorization_code(
        self,
        client: httpx.AsyncClient,
        code: _AuthorizationResponse,
    ) -> CodexOAuthTokenBundle:
        try:
            response = await client.post(
                CODEX_OAUTH_TOKEN_PATH,
                data={
                    "grant_type": "authorization_code",
                    "code": code.authorization_code.get_secret_value(),
                    "redirect_uri": f"{self._issuer}{CODEX_DEVICE_REDIRECT_PATH}",
                    "client_id": CODEX_OAUTH_CLIENT_ID,
                    "code_verifier": code.code_verifier.get_secret_value(),
                },
            )
        except httpx.TimeoutException as error:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.TIMEOUT,
                "Codex OAuth token exchange timed out.",
            ) from error
        except httpx.HTTPError as error:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.LOGIN_UNAVAILABLE,
                "Codex OAuth token exchange failed.",
            ) from error
        if response.status_code != 200:
            raise CodexOAuthProtocolError(
                (
                    CodexOAuthErrorCode.RATE_LIMITED
                    if response.status_code == 429
                    else CodexOAuthErrorCode.LOGIN_UNAVAILABLE
                ),
                "Codex OAuth token exchange failed.",
            )
        result = _validated_json(response, _TokenResponse)
        if result.refresh_token is None or result.id_token is None:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.RESPONSE_INVALID,
                "Codex OAuth token exchange returned an invalid response.",
            )
        bundle = CodexOAuthTokenBundle(
            access_token=result.access_token,
            refresh_token=result.refresh_token,
            id_token=result.id_token,
            obtained_at=self._now(),
        )
        if bundle.expires_at is None or bundle.account_id is None:
            raise CodexOAuthProtocolError(
                CodexOAuthErrorCode.RESPONSE_INVALID,
                "Codex OAuth token exchange returned invalid token metadata.",
            )
        return bundle

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self._issuer,
            timeout=self._timeout,
            transport=self._transport,
            follow_redirects=False,
            headers={"Accept": "application/json", "User-Agent": "netsage/0.1.0.dev0"},
        )

    def _now(self) -> datetime:
        value = self._clock()
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _validated_json[ModelT: BaseModel](response: httpx.Response, model: type[ModelT]) -> ModelT:
    if len(response.content) > _MAX_AUTH_RESPONSE_BYTES:
        raise CodexOAuthProtocolError(
            CodexOAuthErrorCode.RESPONSE_INVALID,
            "Codex OAuth returned an oversized response.",
        )
    try:
        return model.model_validate(response.json())
    except (ValueError, ValidationError) as error:
        raise CodexOAuthProtocolError(
            CodexOAuthErrorCode.RESPONSE_INVALID,
            "Codex OAuth returned an invalid response.",
        ) from error


def _oauth_error_code(response: httpx.Response) -> str | None:
    if len(response.content) > _MAX_AUTH_RESPONSE_BYTES:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    error = payload.get("error")
    if isinstance(error, str):
        return error.casefold()
    if isinstance(error, dict):
        code = error.get("code") or error.get("type")
        if isinstance(code, str):
            return code.casefold()
    code = payload.get("code")
    return code.casefold() if isinstance(code, str) else None


def _retry_delay(response: httpx.Response, attempt: int) -> float:
    value = response.headers.get("Retry-After")
    if value is not None:
        try:
            return float(max(1, min(int(value), 60)))
        except ValueError:
            try:
                parsed = parsedate_to_datetime(value)
                seconds = (parsed - datetime.now(UTC)).total_seconds()
                return float(max(1, min(int(seconds), 60)))
            except (TypeError, ValueError):
                pass
    return float(min(2**attempt, 8))
