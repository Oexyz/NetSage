import json
from collections import deque

import pytest

from netsage.ai.providers.codex import (
    CodexErrorCode,
    CodexProviderError,
    CodexStructuredOutput,
    OfficialCodexAppServerClient,
)
from netsage.ai.providers.codex.client import (
    CodexLineTransport,
    CodexTransportFactory,
    _sanitized_environment,
)


class FakeTransport(CodexLineTransport):
    def __init__(self, responses: tuple[dict[str, object], ...]) -> None:
        self.responses = deque(responses)
        self.sent: list[dict[str, object]] = []
        self.closed = False

    @property
    def working_directory(self) -> str:
        return "C:/synthetic-empty-codex-workspace"

    async def send(self, message: dict[str, object]) -> None:
        self.sent.append(dict(message))

    async def receive(self) -> dict[str, object]:
        if not self.responses:
            raise AssertionError("No scripted Codex protocol response")
        return self.responses.popleft()

    async def close(self) -> None:
        self.closed = True


class FakeFactory(CodexTransportFactory):
    def __init__(self, transport: FakeTransport, *, installed: bool = True) -> None:
        self.transport = transport
        self._executable = "C:/synthetic/codex.exe" if installed else None
        self.starts = 0

    @property
    def executable(self) -> str | None:
        return self._executable

    async def start(self) -> CodexLineTransport:
        self.starts += 1
        return self.transport


def output_json() -> str:
    return CodexStructuredOutput(
        response_type="final",
        summary="No reliable diagnosis is available.",
        diagnosis_strength="insufficient",
        evidence_ids=(),
        limitations=("No evidence supplied.",),
        tool_calls=(),
    ).model_dump_json()


@pytest.mark.asyncio
async def test_codex_account_uses_managed_state_without_email_or_tokens() -> None:
    transport = FakeTransport(
        (
            {"id": 1, "result": {"userAgent": "synthetic"}},
            {
                "id": 2,
                "result": {
                    "account": {
                        "type": "chatgpt",
                        "email": "must-not-be-retained@example.invalid",
                        "planType": "plus",
                    },
                    "requiresOpenaiAuth": True,
                },
            },
        )
    )
    client = OfficialCodexAppServerClient(factory=FakeFactory(transport))

    account = await client.account_state()
    await client.close()

    assert account.installed is True
    assert account.authenticated is True
    assert account.auth_mode == "chatgpt"
    assert account.plan_type == "plus"
    assert "email" not in account.model_dump()
    assert transport.closed is True


@pytest.mark.asyncio
async def test_codex_absence_does_not_start_a_process() -> None:
    transport = FakeTransport(())
    factory = FakeFactory(transport, installed=False)
    client = OfficialCodexAppServerClient(factory=factory)

    account = await client.account_state()

    assert account.installed is False
    assert account.authenticated is False
    assert factory.starts == 0


@pytest.mark.asyncio
async def test_codex_structured_turn_is_ephemeral_read_only_and_tool_free() -> None:
    transport = FakeTransport(
        (
            {"id": 1, "result": {"userAgent": "synthetic"}},
            {"id": 2, "result": {"thread": {"id": "thread-synthetic"}}},
            {"id": 3, "result": {"turn": {"id": "turn-synthetic"}}},
            {
                "method": "item/completed",
                "params": {
                    "item": {
                        "id": "item-synthetic",
                        "type": "agentMessage",
                        "phase": "final_answer",
                        "text": output_json(),
                    }
                },
            },
            {
                "method": "turn/completed",
                "params": {"turn": {"id": "turn-synthetic", "status": "completed"}},
            },
        )
    )
    client = OfficialCodexAppServerClient(factory=FakeFactory(transport))

    output = await client.complete_structured(
        input_text='{"evidence":"synthetic"}',
        instructions="Return structured NetSage data only.",
        reasoning_effort="medium",
    )
    await client.close()

    assert output.response_type == "final"
    thread_request = next(item for item in transport.sent if item.get("method") == "thread/start")
    thread_params = thread_request["params"]
    assert isinstance(thread_params, dict)
    assert thread_params["ephemeral"] is True
    assert thread_params["sandbox"] == "read-only"
    assert thread_params["cwd"] == transport.working_directory
    assert "dynamicTools" not in thread_params
    config = thread_params["config"]
    assert isinstance(config, dict)
    assert config["mcp_servers"] == {}
    turn_request = next(item for item in transport.sent if item.get("method") == "turn/start")
    turn_params = turn_request["params"]
    assert isinstance(turn_params, dict)
    assert turn_params["sandboxPolicy"] == {"type": "readOnly", "networkAccess": False}
    assert "outputSchema" in turn_params


@pytest.mark.asyncio
async def test_codex_tool_item_is_denied_before_completion() -> None:
    transport = FakeTransport(
        (
            {"id": 1, "result": {}},
            {"id": 2, "result": {"thread": {"id": "thread-synthetic"}}},
            {"id": 3, "result": {"turn": {"id": "turn-synthetic"}}},
            {
                "method": "item/started",
                "params": {
                    "item": {
                        "id": "unsafe-item",
                        "type": "commandExecution",
                        "command": "forbidden",
                    }
                },
            },
        )
    )
    client = OfficialCodexAppServerClient(factory=FakeFactory(transport))

    with pytest.raises(CodexProviderError) as caught:
        await client.complete_structured(
            input_text="{}",
            instructions="Do not use tools.",
            reasoning_effort="medium",
        )
    await client.close()

    assert caught.value.code == CodexErrorCode.UNSAFE_TOOL_ATTEMPT.value
    assert all(item.get("id") != 99 for item in transport.sent)


@pytest.mark.asyncio
async def test_codex_server_tool_request_receives_protocol_denial() -> None:
    transport = FakeTransport(
        (
            {"id": 1, "result": {}},
            {"id": 2, "result": {"thread": {"id": "thread-synthetic"}}},
            {"id": 3, "result": {"turn": {"id": "turn-synthetic"}}},
            {
                "id": 99,
                "method": "item/tool/call",
                "params": {"tool": "shell", "arguments": {}},
            },
        )
    )
    client = OfficialCodexAppServerClient(factory=FakeFactory(transport))

    with pytest.raises(CodexProviderError) as caught:
        await client.complete_structured(
            input_text="{}",
            instructions="Do not use tools.",
            reasoning_effort="medium",
        )
    await client.close()

    assert caught.value.code == CodexErrorCode.UNSAFE_TOOL_ATTEMPT.value
    denial = transport.sent[-1]
    assert denial["id"] == 99
    assert "error" in denial


def test_codex_subprocess_environment_excludes_secret_bearing_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "synthetic-environment-secret"
    monkeypatch.setenv("OPENAI_API_KEY", canary)
    monkeypatch.setenv("NETSAGE_DEVICE_PASSWORD", canary)
    monkeypatch.setenv("HTTPS_PROXY", f"https://user:{canary}@proxy.invalid")

    environment = _sanitized_environment()

    assert "OPENAI_API_KEY" not in environment
    assert "NETSAGE_DEVICE_PASSWORD" not in environment
    assert "HTTPS_PROXY" not in environment
    assert canary not in json.dumps(environment)
