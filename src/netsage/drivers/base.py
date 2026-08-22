"""Vendor-neutral, read-only network driver contract."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address

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


class UnsupportedCapabilityError(RuntimeError):
    """Raised instead of simulating data for an unsupported operation."""


class IncompleteCollectionError(RuntimeError):
    """Raised when a focused view cannot represent a truncated collection safely."""


class NetworkDriver(ABC):
    """Expose structured diagnostics without arbitrary command execution."""

    @property
    @abstractmethod
    def capabilities(self) -> frozenset[Capability]: ...

    @abstractmethod
    async def get_facts(self) -> DeviceFacts: ...

    @abstractmethod
    async def get_interfaces(self) -> Sequence[Interface]: ...

    @abstractmethod
    async def get_vlans(self) -> Sequence[VLAN]: ...

    @abstractmethod
    async def get_mac_table(self) -> Sequence[MacEntry]: ...

    @abstractmethod
    async def get_arp_table(self) -> Sequence[ArpEntry]: ...

    @abstractmethod
    async def get_routes(self) -> Sequence[Route]: ...

    @abstractmethod
    async def get_lldp_neighbors(self) -> Sequence[LldpNeighbor]: ...

    @abstractmethod
    async def get_system_health(self) -> SystemHealth: ...

    @abstractmethod
    async def get_firewall_policies(self) -> Sequence[FirewallPolicy]: ...

    @abstractmethod
    async def get_ha_status(self) -> HAStatus: ...

    @abstractmethod
    async def get_ha_members(self) -> Sequence[HAMember]: ...

    @abstractmethod
    async def get_ha_history(self) -> HAHistory: ...

    @abstractmethod
    async def get_ha_checksum_nonsync(self) -> HAChecksumStatus: ...

    @abstractmethod
    async def get_sdwan_status(self) -> SDWANStatus: ...

    @abstractmethod
    async def get_sdwan_members(self) -> Sequence[SDWANMember]: ...

    @abstractmethod
    async def get_sdwan_health_checks(self) -> Sequence[SDWANHealthCheck]: ...

    @abstractmethod
    async def get_ipsec_status(self) -> IPsecStatus: ...

    @abstractmethod
    async def get_ipsec_tunnels(self) -> Sequence[IPsecTunnel]: ...

    @abstractmethod
    async def get_bgp_status(self) -> BGPStatus: ...

    @abstractmethod
    async def get_bgp_neighbors(self) -> Sequence[BGPNeighbor]: ...

    @abstractmethod
    async def get_ospf_status(self) -> OSPFStatus: ...

    @abstractmethod
    async def get_ospf_neighbors(self) -> Sequence[OSPFNeighbor]: ...

    @abstractmethod
    async def get_route_summary(self) -> RouteSummary: ...

    @abstractmethod
    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult: ...

    @abstractmethod
    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult: ...
