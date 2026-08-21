from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address

import pytest

from netsage.ai import (
    AIContext,
    AIFinalResponse,
    AIProvider,
    AIProviderResponse,
    AIToolResult,
    StructuredTool,
)
from netsage.credentials import (
    Credential,
    CredentialKind,
    CredentialProvider,
    DevelopmentEnvironmentCredentialProvider,
    EphemeralCredentialProvider,
    SSHAgentCredentialProvider,
)
from netsage.drivers import NetworkDriver
from netsage.models import (
    VLAN,
    ArpEntry,
    Capability,
    DeviceFacts,
    FirewallPolicy,
    Interface,
    LldpNeighbor,
    MacEntry,
    PingResult,
    Route,
    SystemHealth,
    TracerouteResult,
)


class ExampleDriver(NetworkDriver):
    @property
    def capabilities(self) -> frozenset[Capability]:
        return frozenset(Capability)

    async def get_facts(self) -> DeviceFacts:
        return DeviceFacts(device_id="example", vendor="Example", model="Test", os_version="1")

    async def get_interfaces(self) -> Sequence[Interface]:
        return []

    async def get_vlans(self) -> Sequence[VLAN]:
        return []

    async def get_mac_table(self) -> Sequence[MacEntry]:
        return []

    async def get_arp_table(self) -> Sequence[ArpEntry]:
        return []

    async def get_routes(self) -> Sequence[Route]:
        return []

    async def get_lldp_neighbors(self) -> Sequence[LldpNeighbor]:
        return []

    async def get_system_health(self) -> SystemHealth:
        return SystemHealth(device_id="example", status="healthy")

    async def get_firewall_policies(self) -> Sequence[FirewallPolicy]:
        return []

    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult:
        return PingResult(
            device_id="example",
            destination=destination,
            packets_transmitted=1,
            packets_received=1,
            packet_loss_percent=0,
        )

    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult:
        return TracerouteResult(
            device_id="example",
            destination=destination,
            hops=(),
            reached=False,
        )


class ExampleAIProvider(AIProvider):
    async def generate(
        self,
        context: AIContext,
        *,
        tools: Sequence[StructuredTool],
        tool_results: Sequence[AIToolResult],
    ) -> AIProviderResponse:
        del tools, tool_results
        return AIFinalResponse(
            summary=context.user_request,
            diagnosis_strength="insufficient",
        )


@pytest.mark.asyncio
async def test_driver_contract() -> None:
    driver = ExampleDriver()
    assert (await driver.get_facts()).vendor == "Example"
    assert await driver.get_interfaces() == []
    assert await driver.get_vlans() == []
    assert await driver.get_mac_table() == []
    assert await driver.get_arp_table() == []
    assert await driver.get_routes() == []
    assert await driver.get_lldp_neighbors() == []
    assert (await driver.get_system_health()).status == "healthy"
    assert await driver.get_firewall_policies() == []


@pytest.mark.asyncio
async def test_ai_provider_contract() -> None:
    context = AIContext.model_validate(
        {
            "investigation_id": "00000000-0000-0000-0000-000000000001",
            "user_request": "investigate",
            "device": {
                "device_id": "example",
                "platform": "fortios",
                "capabilities": [],
            },
            "evidence": [],
            "deterministic_findings": [],
            "missing_evidence": [],
        }
    )
    response = await ExampleAIProvider().generate(context, tools=[], tool_results=[])
    assert isinstance(response, AIFinalResponse)
    assert response.summary == "investigate"


def test_credential_repr_does_not_expose_secret() -> None:
    secret = "never" + "-log-this"
    credential = Credential(username="readonly", secret=secret, kind=CredentialKind.PASSWORD)
    assert secret not in repr(credential)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        SSHAgentCredentialProvider(),
        DevelopmentEnvironmentCredentialProvider(),
    ],
)
async def test_unimplemented_credential_providers_fail_closed(
    provider: CredentialProvider,
) -> None:
    with pytest.raises(NotImplementedError):
        await provider.resolve("test-ref")


@pytest.mark.asyncio
async def test_ephemeral_credential_provider_resolves_only_exact_reference() -> None:
    credential = Credential(
        username="readonly",
        secret="test-" + "only-value",
        kind=CredentialKind.PASSWORD,
    )
    provider = EphemeralCredentialProvider("fortigate-live", credential)
    assert await provider.resolve("fortigate-live") is credential
    with pytest.raises(LookupError, match="Unknown ephemeral"):
        await provider.resolve("different-device")
