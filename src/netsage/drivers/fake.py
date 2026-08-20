"""Deterministic driver for tests without network hardware."""

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address

from netsage.drivers.base import NetworkDriver, UnsupportedCapabilityError
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


class FakeDriver(NetworkDriver):
    """Return only explicitly configured typed fixtures."""

    def __init__(
        self,
        *,
        facts: DeviceFacts | None = None,
        interfaces: Sequence[Interface] | None = None,
        vlans: Sequence[VLAN] | None = None,
        mac_table: Sequence[MacEntry] | None = None,
        arp_table: Sequence[ArpEntry] | None = None,
        routes: Sequence[Route] | None = None,
        lldp_neighbors: Sequence[LldpNeighbor] | None = None,
        system_health: SystemHealth | None = None,
        firewall_policies: Sequence[FirewallPolicy] | None = None,
        ping_results: dict[IPv4Address | IPv6Address, PingResult] | None = None,
        traceroute_results: dict[IPv4Address | IPv6Address, TracerouteResult] | None = None,
    ) -> None:
        self._facts = facts
        self._interfaces = tuple(interfaces) if interfaces is not None else None
        self._vlans = tuple(vlans) if vlans is not None else None
        self._mac_table = tuple(mac_table) if mac_table is not None else None
        self._arp_table = tuple(arp_table) if arp_table is not None else None
        self._routes = tuple(routes) if routes is not None else None
        self._lldp_neighbors = tuple(lldp_neighbors) if lldp_neighbors is not None else None
        self._system_health = system_health
        self._firewall_policies = (
            tuple(firewall_policies) if firewall_policies is not None else None
        )
        self._ping_results = ping_results
        self._traceroute_results = traceroute_results

    @property
    def capabilities(self) -> frozenset[Capability]:
        values = {
            capability
            for capability, configured in (
                (Capability.FACTS, self._facts),
                (Capability.INTERFACES, self._interfaces),
                (Capability.VLANS, self._vlans),
                (Capability.MAC_TABLE, self._mac_table),
                (Capability.ARP, self._arp_table),
                (Capability.ROUTES, self._routes),
                (Capability.LLDP, self._lldp_neighbors),
                (Capability.SYSTEM_HEALTH, self._system_health),
                (Capability.FIREWALL, self._firewall_policies),
                (Capability.PING, self._ping_results),
                (Capability.TRACEROUTE, self._traceroute_results),
            )
            if configured is not None
        }
        return frozenset(values)

    def _unsupported(self, capability: Capability) -> UnsupportedCapabilityError:
        return UnsupportedCapabilityError(f"FakeDriver does not support {capability.value}")

    async def get_facts(self) -> DeviceFacts:
        if self._facts is None:
            raise self._unsupported(Capability.FACTS)
        return self._facts

    async def get_interfaces(self) -> Sequence[Interface]:
        if self._interfaces is None:
            raise self._unsupported(Capability.INTERFACES)
        return self._interfaces

    async def get_vlans(self) -> Sequence[VLAN]:
        if self._vlans is None:
            raise self._unsupported(Capability.VLANS)
        return self._vlans

    async def get_mac_table(self) -> Sequence[MacEntry]:
        if self._mac_table is None:
            raise self._unsupported(Capability.MAC_TABLE)
        return self._mac_table

    async def get_arp_table(self) -> Sequence[ArpEntry]:
        if self._arp_table is None:
            raise self._unsupported(Capability.ARP)
        return self._arp_table

    async def get_routes(self) -> Sequence[Route]:
        if self._routes is None:
            raise self._unsupported(Capability.ROUTES)
        return self._routes

    async def get_lldp_neighbors(self) -> Sequence[LldpNeighbor]:
        if self._lldp_neighbors is None:
            raise self._unsupported(Capability.LLDP)
        return self._lldp_neighbors

    async def get_system_health(self) -> SystemHealth:
        if self._system_health is None:
            raise self._unsupported(Capability.SYSTEM_HEALTH)
        return self._system_health

    async def get_firewall_policies(self) -> Sequence[FirewallPolicy]:
        if self._firewall_policies is None:
            raise self._unsupported(Capability.FIREWALL)
        return self._firewall_policies

    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult:
        if self._ping_results is None or destination not in self._ping_results:
            raise self._unsupported(Capability.PING)
        return self._ping_results[destination]

    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult:
        if self._traceroute_results is None or destination not in self._traceroute_results:
            raise self._unsupported(Capability.TRACEROUTE)
        return self._traceroute_results[destination]
