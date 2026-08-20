"""Read-only FortiOS driver using typed commands and normalized parsers."""

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import Protocol

from netsage.drivers.base import NetworkDriver, UnsupportedCapabilityError
from netsage.drivers.fortios.commands import FortiOSCommand, FortiOSRequest
from netsage.drivers.fortios.parsers import (
    parse_arp_table,
    parse_device_facts,
    parse_firewall_policies,
    parse_interfaces,
    parse_ping_result,
    parse_routes,
    parse_system_health,
    parse_traceroute_result,
    parse_vlans,
)
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


class FortiOSTransport(Protocol):
    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]: ...


FORTIOS_CAPABILITIES = frozenset(
    {
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
)


@dataclass(frozen=True, slots=True)
class FortiOSSnapshot:
    facts: DeviceFacts
    interfaces: tuple[Interface, ...]
    vlans: tuple[VLAN, ...]
    arp_entries: tuple[ArpEntry, ...]
    routes: tuple[Route, ...]
    health: SystemHealth
    firewall_policies: tuple[FirewallPolicy, ...]


class FortiOSDriver(NetworkDriver):
    """FortiGate read-only operations with no arbitrary command surface."""

    def __init__(self, device_id: str, transport: FortiOSTransport) -> None:
        self._device_id = device_id
        self._transport = transport

    @property
    def capabilities(self) -> frozenset[Capability]:
        return FORTIOS_CAPABILITIES

    async def get_snapshot(self) -> FortiOSSnapshot:
        """Collect the complete passive milestone data over one SSH connection."""

        status, config, physical, arp, routes, health, policies = await self._transport.execute(
            (
                FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),
                FortiOSRequest(FortiOSCommand.INTERFACE_CONFIGURATION),
                FortiOSRequest(FortiOSCommand.PHYSICAL_INTERFACES),
                FortiOSRequest(FortiOSCommand.ARP_TABLE),
                FortiOSRequest(FortiOSCommand.ROUTES),
                FortiOSRequest(FortiOSCommand.SYSTEM_HEALTH),
                FortiOSRequest(FortiOSCommand.FIREWALL_POLICIES),
            )
        )
        return FortiOSSnapshot(
            facts=parse_device_facts(self._device_id, status),
            interfaces=tuple(parse_interfaces(self._device_id, config, physical)),
            vlans=tuple(parse_vlans(self._device_id, config)),
            arp_entries=tuple(parse_arp_table(self._device_id, arp)),
            routes=tuple(parse_routes(self._device_id, routes)),
            health=parse_system_health(self._device_id, health),
            firewall_policies=tuple(parse_firewall_policies(self._device_id, policies)),
        )

    async def get_facts(self) -> DeviceFacts:
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))
        return parse_device_facts(self._device_id, output)

    async def get_interfaces(self) -> Sequence[Interface]:
        config, physical = await self._transport.execute(
            (
                FortiOSRequest(FortiOSCommand.INTERFACE_CONFIGURATION),
                FortiOSRequest(FortiOSCommand.PHYSICAL_INTERFACES),
            )
        )
        return parse_interfaces(self._device_id, config, physical)

    async def get_vlans(self) -> Sequence[VLAN]:
        (output,) = await self._transport.execute(
            (FortiOSRequest(FortiOSCommand.INTERFACE_CONFIGURATION),)
        )
        return parse_vlans(self._device_id, output)

    async def get_mac_table(self) -> Sequence[MacEntry]:
        raise UnsupportedCapabilityError("FortiOS driver does not support mac_table")

    async def get_arp_table(self) -> Sequence[ArpEntry]:
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.ARP_TABLE),))
        return parse_arp_table(self._device_id, output)

    async def get_routes(self) -> Sequence[Route]:
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.ROUTES),))
        return parse_routes(self._device_id, output)

    async def get_lldp_neighbors(self) -> Sequence[LldpNeighbor]:
        raise UnsupportedCapabilityError("FortiOS driver does not support lldp")

    async def get_system_health(self) -> SystemHealth:
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_HEALTH),))
        return parse_system_health(self._device_id, output)

    async def get_firewall_policies(self) -> Sequence[FirewallPolicy]:
        (output,) = await self._transport.execute(
            (FortiOSRequest(FortiOSCommand.FIREWALL_POLICIES),)
        )
        return parse_firewall_policies(self._device_id, output)

    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult:
        (output,) = await self._transport.execute(
            (FortiOSRequest(FortiOSCommand.PING, destination),)
        )
        return parse_ping_result(self._device_id, str(destination), output)

    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult:
        (output,) = await self._transport.execute(
            (FortiOSRequest(FortiOSCommand.TRACEROUTE, destination),)
        )
        return parse_traceroute_result(self._device_id, str(destination), output)
