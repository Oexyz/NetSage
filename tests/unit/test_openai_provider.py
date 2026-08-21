import json
from collections import deque
from datetime import UTC, datetime
from ipaddress import ip_network
from types import SimpleNamespace
from uuid import UUID

import httpx
import pytest
from openai import APITimeoutError, AuthenticationError, NotFoundError
from pydantic import SecretStr

from netsage.agent import AgentInvestigationRequest, AgentRuntime, AgentRuntimeState
from netsage.ai import AIContext, AIContextBuilder, AIDeviceContext
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OfficialOpenAIServiceClient,
    OpenAIErrorCode,
    OpenAIModel,
    OpenAIProvider,
    OpenAIProviderError,
    OpenAIStructuredOutput,
)
from netsage.ai.providers.openai.client import _safe_openai_error
from netsage.broker import ToolBroker
from netsage.drivers import FakeDriver
from netsage.evidence import EvidenceCollector, EvidenceFactory, InMemoryEvidenceStore
from netsage.inventory import Inventory
from netsage.investigations import (
    DiagnosisStrength,
    Investigation,
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.models import Capability, DeviceRef, Platform, Route
from netsage.state import OpenAIProviderSettings
from netsage.tools import StructuredDriverToolSet

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)
INVESTIGATION_ID = UUID(int=100)
API_KEY_CANARY = "sk-synthetic-provider-canary"


def context() -> AIContext:
    return AIContext(
        investigation_id=INVESTIGATION_ID,
        user_request="Assess the available evidence.",
        device=AIDeviceContext(
            device_id="fortigate-example",
            platform=Platform.FORTIOS,
            capabilities=(Capability.ROUTES,),
        ),
        evidence=(),
        deterministic_findings=(),
        missing_evidence=(),
    )


class FakeOpenAIServiceClient:
    def __init__(
        self,
        responses: tuple[OpenAIStructuredOutput | Exception, ...] = (),
        *,
        models: tuple[OpenAIModel, ...] | None = None,
    ) -> None:
        self.responses = deque(responses)
        self.models = models or (OpenAIModel(id="gpt-5.6-terra", owned_by="openai"),)
        self.inputs: list[str] = []
        self.instructions: list[str] = []
        self.api_keys: list[SecretStr] = []

    async def list_models(self, api_key: SecretStr) -> tuple[OpenAIModel, ...]:
        self.api_keys.append(api_key)
        return self.models

    async def complete_structured(
        self,
        api_key: SecretStr,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: str,
    ) -> OpenAIStructuredOutput:
        self.api_keys.append(api_key)
        self.inputs.append(input_text)
        self.instructions.append(instructions)
        assert model == "gpt-5.6-terra"
        assert reasoning_effort == "medium"
        if not self.responses:
            raise AssertionError("No scripted OpenAI response")
        response = self.responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response


def final_output() -> OpenAIStructuredOutput:
    return OpenAIStructuredOutput(
        response={
            "response_type": "final",
            "summary": "No reliable diagnosis from empty evidence.",
            "diagnosis_strength": "insufficient",
            "evidence_ids": [],
            "limitations": ["No observations supplied."],
        }
    )


@pytest.mark.asyncio
async def test_direct_openai_provider_returns_typed_final_without_codex() -> None:
    service = FakeOpenAIServiceClient((final_output(),))
    provider = OpenAIProvider(
        OpenAIProviderSettings(),
        api_keys=InMemoryOpenAIAPIKeyStore(API_KEY_CANARY),
        client=service,
    )

    response = await provider.generate(context(), tools=(), tool_results=())
    await provider.close()

    assert response.diagnosis_strength is DiagnosisStrength.INSUFFICIENT
    assert API_KEY_CANARY not in service.inputs[0]
    assert "untrusted data" in service.inputs[0]
    assert all(API_KEY_CANARY not in repr(item) for item in service.api_keys)


@pytest.mark.asyncio
async def test_provider_requires_key_and_selected_model() -> None:
    missing = OpenAIProvider(
        OpenAIProviderSettings(),
        api_keys=InMemoryOpenAIAPIKeyStore(),
        client=FakeOpenAIServiceClient(),
    )
    with pytest.raises(OpenAIProviderError) as unauthenticated:
        await missing.initialize()
    assert unauthenticated.value.code == OpenAIErrorCode.NOT_AUTHENTICATED.value

    unavailable = OpenAIProvider(
        OpenAIProviderSettings(model="unavailable-model"),
        api_keys=InMemoryOpenAIAPIKeyStore(API_KEY_CANARY),
        client=FakeOpenAIServiceClient(),
    )
    with pytest.raises(OpenAIProviderError) as missing_model:
        await unavailable.initialize()
    assert missing_model.value.code == OpenAIErrorCode.MODEL_UNAVAILABLE.value


@pytest.mark.asyncio
async def test_fake_driver_to_direct_openai_full_agent_loop() -> None:
    driver = FakeDriver(
        routes=(
            Route(
                device_id="fortigate-example",
                prefix=ip_network("0.0.0.0/0"),
                protocol="static",
                selected=True,
            ),
        )
    )
    device = DeviceRef(
        name="fortigate-example",
        host="192.0.2.10",
        platform=Platform.FORTIOS,
        credential_ref="synthetic-readonly",
        capabilities=driver.capabilities,
    )
    inventory = Inventory(devices={device.name: device})
    broker = ToolBroker(inventory=inventory, ai_provider="openai")
    StructuredDriverToolSet({device.name: driver}).register(broker)
    evidence_ids = iter(UUID(int=value) for value in range(1, 10))
    store = InMemoryEvidenceStore()
    collector = EvidenceCollector(
        broker=broker,
        inventory=inventory,
        factory=EvidenceFactory(
            clock=lambda: NOW,
            evidence_id_factory=lambda: next(evidence_ids),
        ),
        store=store,
        driver="FakeDriver",
        clock=lambda: NOW,
    )

    class ToolLoopClient(FakeOpenAIServiceClient):
        async def complete_structured(
            self,
            api_key: SecretStr,
            *,
            input_text: str,
            instructions: str,
            model: str,
            reasoning_effort: str,
        ) -> OpenAIStructuredOutput:
            self.inputs.append(input_text)
            payload = json.loads(input_text)
            evidence = payload["context"]["evidence"]
            if not evidence:
                return OpenAIStructuredOutput(
                    response={
                        "response_type": "tool_calls",
                        "tool_calls": [
                            {
                                "call_id": "00000000-0000-0000-0000-000000000101",
                                "tool_name": "get_routes",
                                "arguments": {},
                            }
                        ],
                    }
                )
            return OpenAIStructuredOutput(
                response={
                    "response_type": "final",
                    "summary": "Synthetic route evidence is present.",
                    "diagnosis_strength": "probable",
                    "evidence_ids": [evidence[0]["evidence_id"]],
                    "limitations": ["Synthetic test."],
                }
            )

    service = ToolLoopClient()
    provider = OpenAIProvider(
        OpenAIProviderSettings(),
        api_keys=InMemoryOpenAIAPIKeyStore(API_KEY_CANARY),
        client=service,
    )
    runtime = AgentRuntime(
        provider=provider,
        provider_name="OpenAI",
        broker=broker,
        collector=collector,
        evidence_store=store,
        context_builder=AIContextBuilder(),
    )
    deterministic = InvestigationReport(
        investigation=Investigation(
            investigation_id=INVESTIGATION_ID,
            device_id=device.name,
            kind=InvestigationKind.FORTIGATE_HEALTH,
            started_at=NOW,
        ),
        completed_at=NOW,
        status=InvestigationStatus.HEALTHY,
        evidence_ids=(),
    )
    try:
        report = await runtime.run(
            AgentInvestigationRequest(device_id=device.name, question="Check routing."),
            device=device,
            deterministic_report=deterministic,
        )
    finally:
        await provider.close()

    assert report.state is AgentRuntimeState.COMPLETED
    assert report.provider == "OpenAI"
    assert report.ai_assessment is not None
    assert report.ai_assessment.evidence_ids == (UUID(int=1),)
    assert API_KEY_CANARY not in "".join(service.inputs)


@pytest.mark.asyncio
async def test_official_sdk_adapter_disables_tools_and_storage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parsed = final_output()

    class ModelsResource:
        async def list(self) -> object:
            return SimpleNamespace(data=[SimpleNamespace(id="gpt-5.6-terra", owned_by="openai")])

    class ResponsesResource:
        def __init__(self) -> None:
            self.arguments: dict[str, object] = {}

        async def parse(self, **arguments: object) -> object:
            self.arguments = arguments
            return SimpleNamespace(output_parsed=parsed)

    class SDKClient:
        def __init__(self) -> None:
            self.models = ModelsResource()
            self.responses = ResponsesResource()
            self.closed = False

        async def close(self) -> None:
            self.closed = True

    sdk = SDKClient()
    client = OfficialOpenAIServiceClient()
    monkeypatch.setattr(client, "_client", lambda _api_key: sdk)
    key = SecretStr(API_KEY_CANARY)

    models = await client.list_models(key)
    output = await client.complete_structured(
        key,
        input_text="{}",
        instructions="Return structured output.",
        model="gpt-5.6-terra",
        reasoning_effort="medium",
    )

    assert models[0].id == "gpt-5.6-terra"
    assert output == parsed
    assert sdk.responses.arguments["tools"] == []
    assert sdk.responses.arguments["store"] is False
    assert "api_key" not in sdk.responses.arguments


def test_official_sdk_errors_map_to_bounded_categories() -> None:
    request = httpx.Request("GET", "https://api.openai.com/v1/models")
    unauthorized_response = httpx.Response(401, request=request)
    missing_response = httpx.Response(404, request=request)
    raw_canary = "provider-error-secret-canary"

    authentication = _safe_openai_error(
        AuthenticationError(raw_canary, response=unauthorized_response, body=None)
    )
    timeout = _safe_openai_error(APITimeoutError(request=request))
    unavailable = _safe_openai_error(
        NotFoundError(raw_canary, response=missing_response, body=None)
    )
    generic = _safe_openai_error(ValueError(raw_canary))

    assert authentication.code == OpenAIErrorCode.AUTHENTICATION_FAILED.value
    assert timeout.code == OpenAIErrorCode.TIMEOUT.value
    assert unavailable.code == OpenAIErrorCode.MODEL_UNAVAILABLE.value
    assert generic.code == OpenAIErrorCode.API_ERROR.value
    assert all(
        raw_canary not in str(error) for error in (authentication, timeout, unavailable, generic)
    )
