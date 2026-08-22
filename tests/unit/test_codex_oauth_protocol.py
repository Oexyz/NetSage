import base64
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from pydantic import SecretStr

from netsage.ai.providers.openai_codex import (
    CodexOAuthErrorCode,
    CodexOAuthHTTPClient,
    CodexOAuthProtocolError,
    CodexOAuthTokenBundle,
)


def jwt(*, expires_at: datetime, account_id: str = "account-synthetic") -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "exp": int(expires_at.timestamp()),
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": "plus",
        },
    }

    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{encode(header)}.{encode(payload)}.c2ln"


class FakeClock:
    def __init__(self) -> None:
        self.now = datetime(2026, 8, 22, 10, 0, tzinfo=UTC)
        self.sleeps: list[float] = []

    def __call__(self) -> datetime:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += timedelta(seconds=seconds)


def token_response(clock: FakeClock) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "access_token": jwt(expires_at=clock.now + timedelta(hours=1)),
            "refresh_token": "refresh-synthetic",
            "id_token": jwt(expires_at=clock.now + timedelta(hours=1)),
        },
    )


@pytest.mark.asyncio
async def test_device_code_login_succeeds_without_codex_cli_or_api_key() -> None:
    clock = FakeClock()
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path.endswith("/deviceauth/usercode"):
            assert json.loads(request.content) == {"client_id": "app_EMoamEEZ73f0CkXaXp7hrann"}
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-synthetic",
                    "user_code": "ABCD-EFGH",
                    "interval": "1",
                    "expires_in": 900,
                },
            )
        if request.url.path.endswith("/deviceauth/token"):
            return httpx.Response(
                200,
                json={
                    "authorization_code": "authorization-synthetic",
                    "code_verifier": "verifier-synthetic",
                    "code_challenge": "challenge-synthetic",
                },
            )
        if request.url.path.endswith("/oauth/token"):
            return token_response(clock)
        raise AssertionError(request.url)

    client = CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock,
    )

    authorization = await client.request_device_authorization()
    tokens = await client.complete_device_authorization(authorization)

    assert authorization.verification_url == "https://auth.example.invalid/codex/device"
    assert authorization.user_code.get_secret_value() == "ABCD-EFGH"
    assert tokens.account_id == "account-synthetic"
    assert tokens.plan_type == "plus"
    assert all("api.openai.com" not in str(request.url) for request in requests)


@pytest.mark.asyncio
async def test_device_code_authorization_pending_obeys_poll_interval() -> None:
    clock = FakeClock()
    polls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal polls
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-synthetic",
                    "user_code": "ABCD-EFGH",
                    "interval": "2",
                },
            )
        if request.url.path.endswith("/deviceauth/token"):
            polls += 1
            if polls == 1:
                return httpx.Response(403, json={"error": "authorization_pending"})
            return httpx.Response(
                200,
                json={
                    "authorization_code": "authorization-synthetic",
                    "code_verifier": "verifier-synthetic",
                },
            )
        return token_response(clock)

    client = CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock,
    )
    authorization = await client.request_device_authorization()

    await client.complete_device_authorization(authorization)

    assert polls == 2
    assert clock.sleeps == [2.0, 2.0]


@pytest.mark.asyncio
async def test_device_code_slow_down_increases_interval() -> None:
    clock = FakeClock()
    polls = 0

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal polls
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={
                    "device_auth_id": "device-synthetic",
                    "user_code": "ABCD-EFGH",
                    "interval": "1",
                },
            )
        if request.url.path.endswith("/deviceauth/token"):
            polls += 1
            if polls == 1:
                return httpx.Response(429, json={"error": "slow_down"})
            return httpx.Response(
                200,
                json={
                    "authorization_code": "authorization-synthetic",
                    "code_verifier": "verifier-synthetic",
                },
            )
        return token_response(clock)

    client = CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock,
    )
    authorization = await client.request_device_authorization()

    await client.complete_device_authorization(authorization)

    assert clock.sleeps == [1.0, 6.0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("upstream_error", "expected"),
    [
        ("expired_token", CodexOAuthErrorCode.LOGIN_EXPIRED),
        ("access_denied", CodexOAuthErrorCode.ACCESS_DENIED),
    ],
)
async def test_device_code_terminal_errors_are_bounded(
    upstream_error: str,
    expected: CodexOAuthErrorCode,
) -> None:
    clock = FakeClock()

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={"device_auth_id": "device", "user_code": "CODE", "interval": "1"},
            )
        return httpx.Response(400, json={"error": upstream_error})

    client = CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock,
    )
    authorization = await client.request_device_authorization()

    with pytest.raises(CodexOAuthProtocolError) as caught:
        await client.complete_device_authorization(authorization)

    assert caught.value.code is expected
    assert upstream_error not in str(caught.value)


@pytest.mark.asyncio
async def test_malformed_token_response_never_exposes_response_content() -> None:
    clock = FakeClock()
    canary = "oauth-response-secret-canary"

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/deviceauth/usercode"):
            return httpx.Response(
                200,
                json={"device_auth_id": "device", "user_code": "CODE", "interval": "1"},
            )
        if request.url.path.endswith("/deviceauth/token"):
            return httpx.Response(
                200,
                json={"authorization_code": "code", "code_verifier": "verifier"},
            )
        return httpx.Response(200, json={"unexpected": canary})

    client = CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(handler),
        sleep=clock.sleep,
        clock=clock,
    )
    authorization = await client.request_device_authorization()

    with pytest.raises(CodexOAuthProtocolError) as caught:
        await client.complete_device_authorization(authorization)

    assert caught.value.code is CodexOAuthErrorCode.RESPONSE_INVALID
    assert canary not in str(caught.value)


@pytest.mark.asyncio
async def test_refresh_rotates_complete_bundle_and_failure_requires_login() -> None:
    clock = FakeClock()
    original = CodexOAuthTokenBundle(
        access_token=SecretStr(jwt(expires_at=clock.now - timedelta(seconds=1))),
        refresh_token=SecretStr("old-refresh-canary"),
        id_token=SecretStr(jwt(expires_at=clock.now + timedelta(hours=1))),
        obtained_at=clock.now - timedelta(hours=1),
    )

    async def success(request: httpx.Request) -> httpx.Response:
        assert json.loads(request.content)["grant_type"] == "refresh_token"
        return httpx.Response(
            200,
            json={
                "access_token": jwt(expires_at=clock.now + timedelta(hours=1)),
                "refresh_token": "new-refresh-canary",
            },
        )

    refreshed = await CodexOAuthHTTPClient(
        issuer="https://auth.example.invalid",
        transport=httpx.MockTransport(success),
        clock=clock,
    ).refresh_tokens(original)

    assert refreshed.refresh_token.get_secret_value() == "new-refresh-canary"
    assert refreshed.id_token.get_secret_value() == original.id_token.get_secret_value()

    async def failure(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            400,
            json={"error": {"code": "refresh_token_invalidated", "message": "secret"}},
        )

    with pytest.raises(CodexOAuthProtocolError) as caught:
        await CodexOAuthHTTPClient(
            issuer="https://auth.example.invalid",
            transport=httpx.MockTransport(failure),
            clock=clock,
        ).refresh_tokens(original)

    assert caught.value.code is CodexOAuthErrorCode.AUTHENTICATION_EXPIRED
    assert caught.value.reauthentication_required is True
    assert "old-refresh-canary" not in str(caught.value)
