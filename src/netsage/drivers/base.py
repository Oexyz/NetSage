"""Vendor-neutral, read-only network driver contract."""

from abc import ABC, abstractmethod
from collections.abc import Sequence
from ipaddress import IPv4Address, IPv6Address

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


class UnsupportedCapabilityError(RuntimeError):
    """Raised instead of simulating data for an unsupported operation."""


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
    async def ping(self, destination: IPv4Address | IPv6Address) -> PingResult: ...

    @abstractmethod
    async def traceroute(self, destination: IPv4Address | IPv6Address) -> TracerouteResult: ...
