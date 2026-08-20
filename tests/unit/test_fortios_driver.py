from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path

import pytest

from netsage.drivers import UnsupportedCapabilityError
from netsage.drivers.fortios import FortiOSCommand, FortiOSDriver, FortiOSRequest
from netsage.models import Capability

FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"


class FixtureTransport:
    def __init__(self) -> None:
        self.requests: list[FortiOSRequest] = []
        self.outputs = {
            FortiOSCommand.SYSTEM_STATUS: "system_status.txt",
            FortiOSCommand.INTERFACE_CONFIGURATION: "interfaces_config.txt",
            FortiOSCommand.PHYSICAL_INTERFACES: "interfaces_physical.txt",
            FortiOSCommand.ROUTES: "routes.txt",
            FortiOSCommand.ARP_TABLE: "arp_table.txt",
            FortiOSCommand.SYSTEM_HEALTH: "system_health.txt",
            FortiOSCommand.FIREWALL_POLICIES: "firewall_policies.txt",
            FortiOSCommand.PING: "ping.txt",
            FortiOSCommand.TRACEROUTE: "traceroute.txt",
        }

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        self.requests.extend(requests)
        return tuple(
            (FIXTURES / self.outputs[request.command]).read_text(encoding="utf-8")
            for request in requests
        )


@pytest.mark.asyncio
async def test_fortios_driver_exposes_complete_read_only_capabilities() -> None:
    transport = FixtureTransport()
    driver = FortiOSDriver("fortigate-lab", transport)
    destination = ip_address("198.51.100.10")

    assert driver.capabilities == {
        Capability.FACTS,
        Capability.INTERFACES,
        Capability.VLANS,
        Capability.ARP,
        Capability.ROUTES,
        Capability.SYSTEM_HEALTH,
        Capability.FIREWALL,
        Capability.PING,
        Capability.TRACEROUTE,
    }
    assert (await driver.get_facts()).model == "FortiGate-VM64"
    assert len(await driver.get_interfaces()) == 3
    assert len(await driver.get_vlans()) == 1
    assert len(await driver.get_arp_table()) == 2
    assert len(await driver.get_routes()) == 6
    assert (await driver.get_system_health()).cpu_percent == 6
    assert len(await driver.get_firewall_policies()) == 2
    assert (await driver.ping(destination)).successful is True
    assert (await driver.traceroute(destination)).reached is True
    snapshot = await driver.get_snapshot()
    assert snapshot.facts.hostname == "fortigate-lab"
    assert len(snapshot.firewall_policies) == 2

    assert all(request.render() for request in transport.requests)


@pytest.mark.asyncio
async def test_fortios_driver_does_not_simulate_unsupported_features() -> None:
    driver = FortiOSDriver("fortigate-lab", FixtureTransport())
    with pytest.raises(UnsupportedCapabilityError, match="mac_table"):
        await driver.get_mac_table()
    with pytest.raises(UnsupportedCapabilityError, match="lldp"):
        await driver.get_lldp_neighbors()


def test_fortios_request_renders_only_typed_destinations() -> None:
    destination = ip_address("198.51.100.10")
    assert FortiOSRequest(FortiOSCommand.PING, destination).render() == (
        "execute ping 198.51.100.10"
    )
    with pytest.raises(ValueError, match="requires"):
        FortiOSRequest(FortiOSCommand.PING).render()
    with pytest.raises(ValueError, match="not valid"):
        FortiOSRequest(FortiOSCommand.SYSTEM_STATUS, destination).render()
