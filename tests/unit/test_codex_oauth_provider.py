import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import httpx
import pytest
from pydantic import SecretStr

from netsage.ai import AIContext, AIDeviceContext
from netsage.ai.providers.codex import CodexAccountState, CodexStructuredOutput
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OpenAIModel,
    OpenAIServiceClient,
    OpenAIStructuredOutput,
)
from netsage.ai.providers.openai_codex import (
    CodexOAuthInferenceError,
    CodexOAuthProvider,
    CodexOAuthTokenBundle,
    CodexOAuthTokenManager,
    InMemoryCodexOAuthTokenStore,
    OfficialCodexOAuthInferenceClient,
)
from netsage.ai.providers.selection import select_preferred_openai_provider
from netsage.investigations import DiagnosisStrength
from netsage.models import Capability, Platform
from netsage.state import OpenAIProviderSettings

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
ACCESS_CANARY = "oauth-access-provider-canary"
REFRESH_CANARY = "oauth-refresh-provider-canary"


def jwt(*, expires_at: datetime, account_id: str = "account-synthetic") -> str:
    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    payload = {
        "exp": int(expires_at.timestamp()),
        "https://api.openai.com/auth": {
            "chatgpt_account_id": account_id,
            "chatgpt_plan_type": "plus",
        },
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.c2ln"


def tokens() -> CodexOAuthTokenBundle:
    return CodexOAuthTokenBundle(
        access_token=SecretStr(jwt(expires_at=NOW + timedelta(hours=1))),
        refresh_token=SecretStr(REFRESH_CANARY),
        id_token=SecretStr(jwt(expires_at=NOW + timedelta(hours=1))),
        obtained_at=NOW,
    )


def context() -> AIContext:
    return AIContext(
        investigation_id=UUID(int=701),
        user_request="Assess sanitized evidence.",
        device=AIDeviceContext(
            device_id="fortigate-example",
            platform=Platform.FORTIOS,
            capabilities=(Capability.ROUTES,),
        ),
        evidence=(),
        deterministic_findings=(),
        missing_evidence=(),
    )


def final_output() -> CodexStructuredOutput:
    return CodexStructuredOutput(
        response_type="final",
        summary="No evidence-backed diagnosis is available.",
        diagnosis_strength="insufficient",
        evidence_ids=(),
        limitations=("No observations supplied.",),
        tool_calls=(),
    )


@pytest.mark.asyncio
async def test_inference_client_uses_codex_backend_headers_and_no_tools() -> None:
    captured: list[httpx.Request] = []
    output = final_output().model_dump_json()
    stream = (
        f"data: {json.dumps({'type': 'response.output_text.delta', 'delta': output})}\n\n"
        f"data: {json.dumps({'type': 'response.completed', 'response': {'output': []}})}\n\n"
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(request)
        return httpx.Response(200, text=stream, headers={"Content-Type": "text/event-stream"})

    client = OfficialCodexOAuthInferenceClient(
        base_url="https://codex.example.invalid/backend-api/codex",
        transport=httpx.MockTransport(handler),
    )

    result = await client.complete_structured(
        tokens(),
        input_text='{"safe":"context"}',
        instructions="Return typed NetSage output.",
        model="gpt-5.6-terra",
        reasoning_effort="medium",
    )

    assert result.diagnosis_strength is DiagnosisStrength.INSUFFICIENT
    request = captured[0]
    assert request.url.path.endswith("/backend-api/codex/responses")
    assert request.headers["Authorization"].startswith("Bearer ")
    assert request.headers["ChatGPT-Account-ID"] == "account-synthetic"
    assert request.headers["originator"] == "netsage"
    body = json.loads(request.content)
    assert "tools" not in body
    assert "tool_choice" not in body
    assert "parallel_tool_calls" not in body
    assert body["store"] is False
    assert body["stream"] is True
    assert body["text"]["format"]["strict"] is True
    schema = body["text"]["format"]["schema"]
    assert schema["additionalProperties"] is False
    assert schema["required"] == [
        "response_type",
        "summary",
        "diagnosis_strength",
        "evidence_ids",
        "limitations",
        "tool_calls",
    ]
    assert "api_key" not in body


@pytest.mark.asyncio
async def test_inference_errors_and_redirects_never_expose_bearer() -> None:
    bearer = tokens().access_token.get_secret_value()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(307, headers={"Location": "https://attacker.invalid/"})

    client = OfficialCodexOAuthInferenceClient(
        base_url="https://codex.example.invalid/backend-api/codex",
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(CodexOAuthInferenceError) as caught:
        await client.complete_structured(
            tokens(),
            input_text="{}",
            instructions="Safe.",
            model="gpt-5.6-terra",
            reasoning_effort="medium",
        )

    assert bearer not in str(caught.value)
    assert "attacker" not in str(caught.value)


class NeverRefresh:
    async def refresh_tokens(
        self,
        token_bundle: CodexOAuthTokenBundle,
    ) -> CodexOAuthTokenBundle:
        raise AssertionError(token_bundle)


class RecordingInferenceClient:
    def __init__(self) -> None:
        self.inputs: list[str] = []

    async def complete_structured(
        self,
        _tokens: CodexOAuthTokenBundle,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: str,
    ) -> CodexStructuredOutput:
        assert "no authority" in instructions
        assert model == "gpt-5.6-terra"
        assert reasoning_effort == "medium"
        self.inputs.append(input_text)
        return final_output()


@pytest.mark.asyncio
async def test_native_oauth_provider_maps_to_existing_contract_without_token_context() -> None:
    inference = RecordingInferenceClient()
    provider = CodexOAuthProvider(
        OpenAIProviderSettings(),
        tokens=CodexOAuthTokenManager(
            store=InMemoryCodexOAuthTokenStore(tokens()),
            refresh_client=NeverRefresh(),
            clock=lambda: NOW,
        ),
        client=inference,
    )

    result = await provider.generate(context(), tools=(), tool_results=())
    await provider.close()

    assert result.diagnosis_strength is DiagnosisStrength.INSUFFICIENT
    serialized = inference.inputs[0]
    assert ACCESS_CANARY not in serialized
    assert REFRESH_CANARY not in serialized
    assert tokens().access_token.get_secret_value() not in serialized
    assert "untrusted data" in serialized


class InstalledAppServer:
    installed = True

    async def account_state(self) -> CodexAccountState:
        return CodexAccountState(installed=True, authenticated=True, auth_mode="chatgpt")

    async def complete_structured(self, *_args: object, **_kwargs: object) -> CodexStructuredOutput:
        raise AssertionError("native OAuth selection must not use App Server")

    async def close(self) -> None:
        return None


class NeverUsedOpenAI(OpenAIServiceClient):
    async def list_models(self, _api_key: SecretStr) -> tuple[OpenAIModel, ...]:
        raise AssertionError("native OAuth must not cross over to API billing")

    async def complete_structured(
        self, *_args: object, **_kwargs: object
    ) -> OpenAIStructuredOutput:
        raise AssertionError("native OAuth must not cross over to API billing")


def test_auto_selection_prefers_native_oauth_without_token_crossover() -> None:
    oauth = CodexOAuthProvider(
        OpenAIProviderSettings(),
        tokens=CodexOAuthTokenManager(
            store=InMemoryCodexOAuthTokenStore(tokens()),
            refresh_client=NeverRefresh(),
            clock=lambda: NOW,
        ),
        client=RecordingInferenceClient(),
    )

    selected = select_preferred_openai_provider(
        OpenAIProviderSettings(),
        codex_oauth_provider=oauth,
        codex_client=InstalledAppServer(),
        api_keys=InMemoryOpenAIAPIKeyStore("sk-synthetic-api-key"),
        openai_client=NeverUsedOpenAI(),
    )

    assert selected.provider_id == "openai-codex"
    assert selected.provider is oauth


def test_native_oauth_source_has_no_tls_shell_or_api_crossover_bypass() -> None:
    root = Path("src/netsage/ai/providers/openai_codex")
    source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.py"))

    for forbidden in (
        "verify=False",
        "shell=True",
        "os.system",
        "api.openai.com/v1/responses",
        "execute_cli_string",
        "run_arbitrary_command",
    ):
        assert forbidden not in source
