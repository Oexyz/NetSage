from collections.abc import Mapping, Sequence

import pytest

from netsage.ai import AIProvider, AIResponse, StructuredTool
from netsage.credentials import (
    Credential,
    CredentialKind,
    CredentialProvider,
    DevelopmentEnvironmentCredentialProvider,
    KeyringCredentialProvider,
    SSHAgentCredentialProvider,
)
from netsage.drivers import NetworkDriver
from netsage.models import (
    VLAN,
    ArpEntry,
    Capability,
    DeviceFacts,
    Interface,
    LldpNeighbor,
    MacEntry,
    Route,
    SystemHealth,
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


class ExampleAIProvider(AIProvider):
    async def investigate(
        self,
        prompt: str,
        *,
        tools: Sequence[StructuredTool],
        context: Mapping[str, object],
    ) -> AIResponse:
        return AIResponse(text=prompt, tool_calls=({"tool": tools[0].name, "context": context},))


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


@pytest.mark.asyncio
async def test_ai_provider_contract() -> None:
    tool = StructuredTool(name="get_facts", description="facts", input_schema={})
    response = await ExampleAIProvider().investigate("investigate", tools=[tool], context={})
    assert response.text == "investigate"
    assert response.tool_calls[0]["tool"] == "get_facts"


def test_credential_repr_does_not_expose_secret() -> None:
    secret = "never" + "-log-this"
    credential = Credential(username="readonly", secret=secret, kind=CredentialKind.PASSWORD)
    assert secret not in repr(credential)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "provider",
    [
        KeyringCredentialProvider(),
        SSHAgentCredentialProvider(),
        DevelopmentEnvironmentCredentialProvider(),
    ],
)
async def test_unimplemented_credential_providers_fail_closed(
    provider: CredentialProvider,
) -> None:
    with pytest.raises(NotImplementedError):
        await provider.resolve("test-ref")
