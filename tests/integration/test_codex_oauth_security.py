import base64
import json
import logging
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

import pytest
from pydantic import SecretStr

from netsage.agent import AgentRuntimeState, FortiOSAIInvestigationService, render_agent_report
from netsage.ai.providers.codex import CodexStructuredOutput
from netsage.ai.providers.openai_codex import (
    CodexOAuthProvider,
    CodexOAuthTokenBundle,
    CodexOAuthTokenManager,
    InMemoryCodexOAuthTokenStore,
)
from netsage.credentials import CredentialProfile, CredentialSecretStore
from netsage.drivers import FakeDriver
from netsage.history import SQLiteAuditSink, SQLiteInvestigationStore
from netsage.models import DeviceFacts, DeviceRef, HealthStatus, Interface, Route, SystemHealth
from netsage.onboarding import PreparedFortiOSRuntime
from netsage.security import SecretRedactor
from netsage.state import LocalState, OpenAIProviderSettings, SSHHostTrustRecord, StatePaths

NOW = datetime(2026, 8, 22, 14, 0, tzinfo=UTC)
REFRESH_TOKEN_CANARY = "oauth-refresh-security-canary"  # noqa: S105
API_KEY_CANARY = "sk-synthetic-separate-api-canary"
NETWORK_PASSWORD_CANARY = "fortigate-password-security-canary"  # noqa: S105
CREDENTIAL_REFERENCE_CANARY = "credential-reference-security-canary"


def jwt(*, marker: str) -> str:
    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    payload = {
        "exp": int((NOW + timedelta(hours=1)).timestamp()),
        "marker": marker,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "account-synthetic",
            "chatgpt_plan_type": "plus",
        },
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.c2ln"


class NeverUsedSecretStore(CredentialSecretStore):
    def set_secret(self, profile_name: str, secret: str) -> None:
        raise AssertionError((profile_name, secret))

    def get_secret(self, profile_name: str) -> str:
        raise AssertionError(profile_name)

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        raise AssertionError((profile_name, missing_ok))


class NeverRefresh:
    async def refresh_tokens(
        self,
        token_bundle: CodexOAuthTokenBundle,
    ) -> CodexOAuthTokenBundle:
        raise AssertionError(token_bundle)


class RecordingInference:
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
        return CodexStructuredOutput(
            response_type="final",
            summary="No additional diagnosis is available.",
            diagnosis_strength="insufficient",
            evidence_ids=(),
            limitations=("Endpoint evidence is unavailable.",),
            tool_calls=(),
        )


class FakeRuntimeFactory:
    def __init__(self, prepared: PreparedFortiOSRuntime) -> None:
        self.prepared = prepared

    async def prepare(self, device: DeviceRef) -> PreparedFortiOSRuntime:
        assert device == self.prepared.device
        return self.prepared


@pytest.mark.asyncio
async def test_oauth_and_network_canaries_never_cross_persistence_or_ai_boundaries(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.credentials.add(
        CredentialProfile(
            name=CREDENTIAL_REFERENCE_CANARY,
            username="synthetic-readonly-user",
        )
    )
    device = DeviceRef(
        name="fortigate-example",
        host="192.0.2.77",
        port=22,
        platform="fortios",
        credential_ref=CREDENTIAL_REFERENCE_CANARY,
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
    access_token = jwt(marker="oauth-access-security-canary")
    id_token = jwt(marker="oauth-id-security-canary")
    token_bundle = CodexOAuthTokenBundle(
        access_token=SecretStr(access_token),
        refresh_token=SecretStr(REFRESH_TOKEN_CANARY),
        id_token=SecretStr(id_token),
        obtained_at=NOW,
    )
    recording = RecordingInference()
    provider = CodexOAuthProvider(
        OpenAIProviderSettings(),
        tokens=CodexOAuthTokenManager(
            store=InMemoryCodexOAuthTokenStore(token_bundle),
            refresh_client=NeverRefresh(),
            clock=lambda: NOW,
        ),
        client=recording,
    )
    prepared = PreparedFortiOSRuntime(
        device=device,
        driver=driver,  # type: ignore[arg-type]
        redactor=SecretRedactor(known_secrets=(NETWORK_PASSWORD_CANARY,)),
    )
    service = FortiOSAIInvestigationService(
        state=state,
        secrets=NeverUsedSecretStore(),
        provider=provider,
        provider_name="openai-codex",
        runtime=FakeRuntimeFactory(prepared),  # type: ignore[arg-type]
    )

    report = await service.ask(device.name, "Check system health and routing.")

    assert report.state is AgentRuntimeState.COMPLETED
    events = SQLiteAuditSink(state.history).list(limit=20)
    assert events
    assert all(event.ai_provider == "openai-codex" for event in events)
    assert SQLiteInvestigationStore(state.history).list() == ()
    serialized = "\n".join(
        (
            "".join(recording.inputs),
            report.model_dump_json(),
            render_agent_report(report),
            "".join(event.model_dump_json() for event in events),
            caplog.text,
        )
    ).encode()
    persisted = b"".join(path.read_bytes() for path in state.paths.root.iterdir())
    canaries = (
        access_token,
        REFRESH_TOKEN_CANARY,
        id_token,
        API_KEY_CANARY,
        NETWORK_PASSWORD_CANARY,
        CREDENTIAL_REFERENCE_CANARY,
    )
    for canary in canaries:
        assert canary.encode() not in serialized
        if canary not in {CREDENTIAL_REFERENCE_CANARY}:
            assert canary.encode() not in persisted
