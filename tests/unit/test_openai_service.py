import json
from ipaddress import ip_network
from pathlib import Path

import pytest
from pydantic import SecretStr

from netsage.agent import AgentRuntimeState, FortiOSOpenAIInvestigationService
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OpenAIModel,
    OpenAIProvider,
    OpenAIStructuredOutput,
)
from netsage.credentials import CredentialProfile, CredentialSecretStore
from netsage.drivers import FakeDriver
from netsage.history import SQLiteAuditSink, SQLiteInvestigationStore
from netsage.models import (
    DeviceFacts,
    DeviceRef,
    HealthStatus,
    Interface,
    Route,
    SystemHealth,
)
from netsage.onboarding import PreparedFortiOSRuntime
from netsage.security import SecretRedactor
from netsage.state import LocalState, OpenAIProviderSettings, SSHHostTrustRecord, StatePaths

HOST_CANARY = "198.51.100.77"
CREDENTIAL_CANARY = "credential-reference-canary"
USERNAME_CANARY = "username-canary"
NETWORK_SECRET_CANARY = "network-secret-canary"  # noqa: S105 - synthetic leak detector
API_KEY_CANARY = "sk-synthetic-api-canary"


class NeverUsedSecretStore(CredentialSecretStore):
    def set_secret(self, profile_name: str, secret: str) -> None:
        raise AssertionError((profile_name, secret))

    def get_secret(self, profile_name: str) -> str:
        raise AssertionError(profile_name)

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        raise AssertionError((profile_name, missing_ok))


class RecordingOpenAIClient:
    def __init__(self) -> None:
        self.payloads: list[str] = []

    async def list_models(self, _api_key: SecretStr) -> tuple[OpenAIModel, ...]:
        return (OpenAIModel(id="gpt-5.6-terra", owned_by="openai"),)

    async def complete_structured(
        self,
        _api_key: SecretStr,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: str,
    ) -> OpenAIStructuredOutput:
        self.payloads.append(input_text)
        return OpenAIStructuredOutput(
            response={
                "response_type": "final",
                "summary": "No reliable diagnosis from the available evidence.",
                "diagnosis_strength": "insufficient",
                "evidence_ids": [],
                "limitations": ["Endpoint evidence is unavailable."],
            }
        )


class FakeRuntimeFactory:
    def __init__(self, prepared: PreparedFortiOSRuntime) -> None:
        self.prepared = prepared

    async def prepare(self, device: DeviceRef) -> PreparedFortiOSRuntime:
        assert device == self.prepared.device
        return self.prepared


@pytest.mark.asyncio
async def test_fortios_openai_service_excludes_infrastructure_and_provider_secrets(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.credentials.add(CredentialProfile(name=CREDENTIAL_CANARY, username=USERNAME_CANARY))
    device = DeviceRef(
        name="fortigate-example",
        host=HOST_CANARY,
        port=22,
        platform="fortios",
        credential_ref=CREDENTIAL_CANARY,
        trust_ref="fortigate-example",
        capabilities=frozenset({"facts", "interfaces", "routes", "system_health"}),
    )
    state.host_trust.add(
        SSHHostTrustRecord(
            name=device.name,
            host=device.host,
            port=device.port,
            algorithm="ssh-ed25519",
            fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    state.inventory.add(device)
    driver = FakeDriver(
        facts=DeviceFacts(
            device_id=device.name,
            vendor="Fortinet",
            model="Synthetic",
            os_version="test",
        ),
        interfaces=(
            Interface(
                device_id=device.name,
                name="port1",
                admin_state="up",
                operational_state="up",
            ),
        ),
        routes=(
            Route(
                device_id=device.name,
                prefix=ip_network("0.0.0.0/0"),
                protocol="static",
                selected=True,
            ),
        ),
        system_health=SystemHealth(device_id=device.name, status=HealthStatus.HEALTHY),
    )
    recording = RecordingOpenAIClient()
    provider = OpenAIProvider(
        OpenAIProviderSettings(),
        api_keys=InMemoryOpenAIAPIKeyStore(API_KEY_CANARY),
        client=recording,
    )
    prepared = PreparedFortiOSRuntime(
        device=device,
        driver=driver,  # type: ignore[arg-type]
        redactor=SecretRedactor(known_secrets=(NETWORK_SECRET_CANARY,)),
    )
    service = FortiOSOpenAIInvestigationService(
        state=state,
        secrets=NeverUsedSecretStore(),
        provider=provider,
        runtime=FakeRuntimeFactory(prepared),  # type: ignore[arg-type]
    )

    report = await service.ask(device.name, "Check for obvious health or routing issues.")

    assert report.state is AgentRuntimeState.COMPLETED
    payload = recording.payloads[0]
    for canary in (
        HOST_CANARY,
        CREDENTIAL_CANARY,
        USERNAME_CANARY,
        NETWORK_SECRET_CANARY,
        API_KEY_CANARY,
    ):
        assert canary not in payload
    assert SQLiteInvestigationStore(state.history).list() == ()
    events = SQLiteAuditSink(state.history).list(limit=20)
    assert events
    assert all(event.ai_provider == "openai" for event in events)
    assert API_KEY_CANARY not in json.dumps([event.model_dump(mode="json") for event in events])
