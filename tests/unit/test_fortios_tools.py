from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

import pytest

from netsage.broker import AuditResult, AuthorizationDeniedError, InMemoryAuditSink, ToolBroker
from netsage.drivers.fortios import FortiOSCommand, FortiOSDriver, FortiOSRequest
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
        FortiOSCommand.PING: "ping.txt",
        FortiOSCommand.TRACEROUTE: "traceroute.txt",
    }

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        return tuple(
            (FIXTURES / self.outputs[request.command]).read_text(encoding="utf-8")
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

    assert facts.output["result"]["vendor"] == "Fortinet"  # type: ignore[index]
    assert policies.content_trust == "untrusted_device_data"
    assert len(policies.output["results"]) == 2  # type: ignore[arg-type]
    assert all(event.credential_exposed is False for event in audit.events)


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
