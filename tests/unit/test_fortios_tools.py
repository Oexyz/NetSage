from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

import pytest

from netsage.broker import AuditResult, AuthorizationDeniedError, InMemoryAuditSink, ToolBroker
from netsage.drivers.fortios import (
    FortiOSCommand,
    FortiOSDriver,
    FortiOSRequest,
    FortiOSSemanticCommand,
    FortiOSSemanticRequest,
)
from netsage.inventory import Inventory
from netsage.models import DeviceRef
from netsage.policies import ObservePolicy
from netsage.tools import FortiOSToolSet

FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"


class FixtureTransport:
    outputs: ClassVar[dict[FortiOSCommand, str]] = {
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
    semantic_outputs: ClassVar[dict[FortiOSSemanticCommand, str]] = {
        FortiOSSemanticCommand.SDWAN_HEALTH_CHECKS: "sdwan_health_checks.txt",
        FortiOSSemanticCommand.IPSEC_PHASE1: "ipsec_phase1.txt",
        FortiOSSemanticCommand.IPSEC_TUNNELS: "ipsec_tunnels.txt",
    }

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        return tuple(
            (FIXTURES / self.outputs[request.command]).read_text(encoding="utf-8")
            for request in requests
        )

    async def execute_semantic(
        self, requests: Sequence[FortiOSRequest | FortiOSSemanticRequest]
    ) -> tuple[str, ...]:
        return tuple(
            (
                FIXTURES
                / (
                    self.outputs[request.command]
                    if isinstance(request, FortiOSRequest)
                    else self.semantic_outputs[request.command]
                )
            ).read_text(encoding="utf-8")
            for request in requests
        )


def make_device(driver: FortiOSDriver) -> DeviceRef:
    return DeviceRef(
        name="fortigate-lab",
        host="192.0.2.1",
        platform="fortios",
        credential_ref="fortigate-readonly",
        capabilities=driver.capabilities,
    )


@pytest.mark.asyncio
async def test_fortios_tools_return_normalized_untrusted_results_and_audit() -> None:
    driver = FortiOSDriver("fortigate-lab", FixtureTransport())
    device = make_device(driver)
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=Inventory(devices={device.name: device}),
        audit_sink=audit,
        ai_provider="fake",
    )
    FortiOSToolSet({device.name: driver}).register(broker)

    facts = await broker.invoke("get_device_facts", {"device": device.name})
    policies = await broker.invoke("get_firewall_policies", {"device": device.name})
    ha = await broker.invoke("get_ha_status", {"device": device.name})
    sdwan = await broker.invoke("get_sdwan_status", {"device": device.name})
    ipsec = await broker.invoke("get_ipsec_status", {"device": device.name})
    bgp = await broker.invoke("get_bgp_status", {"device": device.name})
    ospf = await broker.invoke("get_ospf_status", {"device": device.name})

    assert facts.output["result"]["vendor"] == "Fortinet"  # type: ignore[index]
    assert policies.content_trust == "untrusted_device_data"
    assert len(policies.output["results"]) == 2  # type: ignore[arg-type]
    assert len(ha.output["result"]["members"]) == 2  # type: ignore[index]
    assert len(sdwan.output["result"]["health_checks"]) == 2  # type: ignore[index]
    assert len(ipsec.output["result"]["tunnels"]) == 2  # type: ignore[index]
    assert len(bgp.output["result"]["neighbors"]) == 2  # type: ignore[index]
    assert len(ospf.output["result"]["neighbors"]) == 2  # type: ignore[index]
    assert all(event.credential_exposed is False for event in audit.events)
    ai_tools = {definition.name for definition in broker.ai_tools_for_device(device.name)}
    assert {
        "get_ha_status",
        "get_sdwan_status",
        "get_ipsec_status",
        "get_bgp_status",
        "get_ospf_status",
    } <= ai_tools
    assert "get_ha_members" not in ai_tools
    assert "get_route_summary" not in ai_tools


@pytest.mark.asyncio
async def test_diagnostics_require_explicit_observe_policy_permission() -> None:
    driver = FortiOSDriver("fortigate-lab", FixtureTransport())
    device = make_device(driver)
    inventory = Inventory(devices={device.name: device})
    denied = ToolBroker(inventory=inventory)
    FortiOSToolSet({device.name: driver}).register(denied)

    arguments = {"device": device.name, "destination": "198.51.100.10"}
    with pytest.raises(AuthorizationDeniedError, match="diagnostic"):
        await denied.invoke("ping", arguments)

    allowed = ToolBroker(
        inventory=inventory,
        policy=ObservePolicy(allowed_diagnostics=frozenset({"ping", "traceroute"})),
    )
    FortiOSToolSet({device.name: driver}).register(allowed)
    ping = await allowed.invoke("ping", arguments)
    trace = await allowed.invoke("traceroute", arguments)
    assert ping.output["result"]["packets_received"] == 5  # type: ignore[index]
    assert trace.output["result"]["reached"] is True  # type: ignore[index]


@pytest.mark.asyncio
async def test_diagnostic_destination_cannot_become_a_command() -> None:
    driver = FortiOSDriver("fortigate-lab", FixtureTransport())
    device = make_device(driver)
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=Inventory(devices={device.name: device}),
        policy=ObservePolicy(allowed_diagnostics=frozenset({"ping"})),
        audit_sink=audit,
    )
    FortiOSToolSet({device.name: driver}).register(broker)

    with pytest.raises(ValueError):
        await broker.invoke(
            "ping",
            {"device": device.name, "destination": "198.51.100.10; execute reboot"},
        )
    assert audit.events[-1].result is AuditResult.FAILURE
    assert audit.events[-1].configuration_changed is False
