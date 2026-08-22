from collections.abc import Sequence
from ipaddress import ip_address
from pathlib import Path

import pytest

from netsage.drivers import UnsupportedCapabilityError
from netsage.drivers.fortios import (
    FortiOSCommand,
    FortiOSDriver,
    FortiOSRequest,
    FortiOSSemanticCommand,
    FortiOSSemanticRequest,
)
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
            FortiOSCommand.HA_STATUS: "ha_status.txt",
            FortiOSCommand.SDWAN_MEMBERS: "sdwan_members.txt",
            FortiOSCommand.BGP_SUMMARY: "bgp_summary.txt",
            FortiOSCommand.OSPF_STATUS: "ospf_status.txt",
            FortiOSCommand.OSPF_NEIGHBORS: "ospf_neighbors.txt",
            FortiOSCommand.PING: "ping.txt",
            FortiOSCommand.TRACEROUTE: "traceroute.txt",
        }
        self.semantic_outputs = {
            FortiOSSemanticCommand.SDWAN_HEALTH_CHECKS: "sdwan_health_checks.txt",
            FortiOSSemanticCommand.IPSEC_PHASE1: "ipsec_phase1.txt",
            FortiOSSemanticCommand.IPSEC_TUNNELS: "ipsec_tunnels.txt",
        }

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        self.requests.extend(requests)
        return tuple(
            (FIXTURES / self.outputs[request.command]).read_text(encoding="utf-8")
            for request in requests
        )

    async def execute_semantic(
        self, requests: Sequence[FortiOSRequest | FortiOSSemanticRequest]
    ) -> tuple[str, ...]:
        results = []
        for request in requests:
            if isinstance(request, FortiOSRequest):
                self.requests.append(request)
                filename = self.outputs[request.command]
            else:
                filename = self.semantic_outputs[request.command]
            results.append((FIXTURES / filename).read_text(encoding="utf-8"))
        return tuple(results)


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
        Capability.HA,
        Capability.SDWAN,
        Capability.IPSEC,
        Capability.BGP,
        Capability.OSPF,
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
    assert len((await driver.get_ha_status()).members) == 2
    assert len(await driver.get_ha_members()) == 2
    assert len((await driver.get_sdwan_status()).health_checks) == 2
    assert len(await driver.get_sdwan_members()) == 2
    assert len(await driver.get_sdwan_health_checks()) == 2
    assert len((await driver.get_ipsec_status()).tunnels) == 2
    assert len(await driver.get_ipsec_tunnels()) == 2
    assert len((await driver.get_bgp_status()).neighbors) == 2
    assert len(await driver.get_bgp_neighbors()) == 2
    assert len((await driver.get_ospf_status()).neighbors) == 2
    assert len(await driver.get_ospf_neighbors()) == 2
    assert (await driver.get_route_summary()).active_default_routes == 1
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

    semantic = FortiOSSemanticRequest(FortiOSSemanticCommand.IPSEC_TUNNELS)
    assert semantic.render() == "diagnose vpn tunnel list"
