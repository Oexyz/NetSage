"""Deterministic driver for tests without network hardware."""

from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address

from netsage.drivers.base import (
    IncompleteCollectionError,
    NetworkDriver,
    UnsupportedCapabilityError,
)
from netsage.models import (
    VLAN,
    ArpEntry,
    BGPNeighbor,
    BGPStatus,
    Capability,
    DeviceFacts,
    FirewallPolicy,
    HAChecksumStatus,
    HAHistory,
    HAMember,
    HAStatus,
    Interface,
    IPsecStatus,
    IPsecTunnel,
    LldpNeighbor,
    MacEntry,
    OSPFNeighbor,
    OSPFStatus,
    PingResult,
    Route,
    RouteSummary,
    SDWANHealthCheck,
    SDWANMember,
    SDWANStatus,
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
        ha_status: HAStatus | None = None,
        ha_members: Sequence[HAMember] | None = None,
        ha_history: HAHistory | None = None,
        ha_checksum_nonsync: HAChecksumStatus | None = None,
        sdwan_status: SDWANStatus | None = None,
        sdwan_members: Sequence[SDWANMember] | None = None,
        sdwan_health_checks: Sequence[SDWANHealthCheck] | None = None,
        ipsec_status: IPsecStatus | None = None,
        ipsec_tunnels: Sequence[IPsecTunnel] | None = None,
        bgp_status: BGPStatus | None = None,
        bgp_neighbors: Sequence[BGPNeighbor] | None = None,
        ospf_status: OSPFStatus | None = None,
        ospf_neighbors: Sequence[OSPFNeighbor] | None = None,
        route_summary: RouteSummary | None = None,
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
        self._ha_status = ha_status
        self._ha_members = tuple(ha_members) if ha_members is not None else None
        self._ha_history = ha_history
        self._ha_checksum_nonsync = ha_checksum_nonsync
        self._sdwan_status = sdwan_status
        self._sdwan_members = tuple(sdwan_members) if sdwan_members is not None else None
        self._sdwan_health_checks = (
            tuple(sdwan_health_checks) if sdwan_health_checks is not None else None
        )
        self._ipsec_status = ipsec_status
        self._ipsec_tunnels = tuple(ipsec_tunnels) if ipsec_tunnels is not None else None
        self._bgp_status = bgp_status
        self._bgp_neighbors = tuple(bgp_neighbors) if bgp_neighbors is not None else None
        self._ospf_status = ospf_status
        self._ospf_neighbors = tuple(ospf_neighbors) if ospf_neighbors is not None else None
        self._route_summary = route_summary
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
                (
                    Capability.ROUTES,
                    self._routes if self._routes is not None else self._route_summary,
                ),
                (Capability.LLDP, self._lldp_neighbors),
                (Capability.SYSTEM_HEALTH, self._system_health),
                (Capability.FIREWALL, self._firewall_policies),
                (
                    Capability.HA,
                    self._ha_status
                    if self._ha_status is not None
                    else (
                        self._ha_members
                        if self._ha_members is not None
                        else (
                            self._ha_history
                            if self._ha_history is not None
                            else self._ha_checksum_nonsync
                        )
                    ),
                ),
                (
                    Capability.SDWAN,
                    self._sdwan_status
                    if self._sdwan_status is not None
                    else (
                        self._sdwan_members
                        if self._sdwan_members is not None
                        else self._sdwan_health_checks
                    ),
                ),
                (
                    Capability.IPSEC,
                    self._ipsec_status if self._ipsec_status is not None else self._ipsec_tunnels,
                ),
                (
                    Capability.BGP,
                    self._bgp_status if self._bgp_status is not None else self._bgp_neighbors,
                ),
                (
                    Capability.OSPF,
                    self._ospf_status if self._ospf_status is not None else self._ospf_neighbors,
                ),
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

    async def get_ha_status(self) -> HAStatus:
        if self._ha_status is None:
            raise self._unsupported(Capability.HA)
        return self._ha_status

    async def get_ha_members(self) -> Sequence[HAMember]:
        if self._ha_members is not None:
            return self._ha_members
        if self._ha_status is not None:
            if self._ha_status.truncated:
                raise IncompleteCollectionError("Fake HA member collection was truncated")
            return self._ha_status.members
        raise self._unsupported(Capability.HA)

    async def get_ha_history(self) -> HAHistory:
        if self._ha_history is None:
            raise self._unsupported(Capability.HA)
        return self._ha_history

    async def get_ha_checksum_nonsync(self) -> HAChecksumStatus:
        if self._ha_checksum_nonsync is None:
            raise self._unsupported(Capability.HA)
        return self._ha_checksum_nonsync

    async def get_sdwan_status(self) -> SDWANStatus:
        if self._sdwan_status is None:
            raise self._unsupported(Capability.SDWAN)
        return self._sdwan_status

    async def get_sdwan_members(self) -> Sequence[SDWANMember]:
        if self._sdwan_members is not None:
            return self._sdwan_members
        if self._sdwan_status is not None:
            if self._sdwan_status.truncated:
                raise IncompleteCollectionError("Fake SD-WAN member collection was truncated")
            return self._sdwan_status.members
        raise self._unsupported(Capability.SDWAN)

    async def get_sdwan_health_checks(self) -> Sequence[SDWANHealthCheck]:
        if self._sdwan_health_checks is not None:
            return self._sdwan_health_checks
        if self._sdwan_status is not None:
            if self._sdwan_status.truncated:
                raise IncompleteCollectionError("Fake SD-WAN health-check collection was truncated")
            return self._sdwan_status.health_checks
        raise self._unsupported(Capability.SDWAN)

    async def get_ipsec_status(self) -> IPsecStatus:
        if self._ipsec_status is None:
            raise self._unsupported(Capability.IPSEC)
        return self._ipsec_status

    async def get_ipsec_tunnels(self) -> Sequence[IPsecTunnel]:
        if self._ipsec_tunnels is not None:
            return self._ipsec_tunnels
        if self._ipsec_status is not None:
            if self._ipsec_status.truncated:
                raise IncompleteCollectionError("Fake IPsec tunnel collection was truncated")
            return self._ipsec_status.tunnels
        raise self._unsupported(Capability.IPSEC)

    async def get_bgp_status(self) -> BGPStatus:
        if self._bgp_status is None:
            raise self._unsupported(Capability.BGP)
        return self._bgp_status

    async def get_bgp_neighbors(self) -> Sequence[BGPNeighbor]:
        if self._bgp_neighbors is not None:
            return self._bgp_neighbors
        if self._bgp_status is not None:
            if self._bgp_status.truncated:
                raise IncompleteCollectionError("Fake BGP neighbor collection was truncated")
            return self._bgp_status.neighbors
        raise self._unsupported(Capability.BGP)

    async def get_ospf_status(self) -> OSPFStatus:
        if self._ospf_status is None:
            raise self._unsupported(Capability.OSPF)
        return self._ospf_status

    async def get_ospf_neighbors(self) -> Sequence[OSPFNeighbor]:
        if self._ospf_neighbors is not None:
            return self._ospf_neighbors
        if self._ospf_status is not None:
            if self._ospf_status.truncated:
                raise IncompleteCollectionError("Fake OSPF neighbor collection was truncated")
            return self._ospf_status.neighbors
        raise self._unsupported(Capability.OSPF)

    async def get_route_summary(self) -> RouteSummary:
        if self._route_summary is None:
            raise self._unsupported(Capability.ROUTES)
        return self._route_summary

    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult:
        if self._ping_results is None or destination not in self._ping_results:
            raise self._unsupported(Capability.PING)
        return self._ping_results[destination]

    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult:
        if self._traceroute_results is None or destination not in self._traceroute_results:
            raise self._unsupported(Capability.TRACEROUTE)
        return self._traceroute_results[destination]
