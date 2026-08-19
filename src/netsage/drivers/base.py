"""Vendor-neutral, read-only network driver contract."""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from typing import Any


class NetworkDriver(ABC):
    """Expose structured diagnostics without arbitrary command execution."""

    @abstractmethod
    async def get_facts(self) -> Mapping[str, Any]: ...

    @abstractmethod
    async def get_interfaces(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_vlans(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_mac_table(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_arp_table(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_routes(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_lldp_neighbors(self) -> Sequence[Mapping[str, Any]]: ...

    @abstractmethod
    async def get_system_health(self) -> Mapping[str, Any]: ...
