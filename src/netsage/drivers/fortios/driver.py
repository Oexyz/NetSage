"""Read-only FortiOS driver using typed commands and normalized parsers."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address
from typing import TYPE_CHECKING, Protocol

from netsage.drivers.base import (
    IncompleteCollectionError,
    NetworkDriver,
    UnsupportedCapabilityError,
)
from netsage.drivers.fortios.commands import (
    FortiOSCommand,
    FortiOSRequest,
    FortiOSSemanticCommand,
    FortiOSSemanticRequest,
)
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
from netsage.drivers.fortios.semantic import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
    parse_bgp_neighbors_status,
    parse_bgp_status,
    parse_ha_status,
    parse_ipsec_status,
    parse_ospf_status,
    parse_sdwan_status,
    summarize_routes,
)
from netsage.drivers.fortios.transport import FortiOSCommandUnavailableError
from netsage.drivers.fortios.variants import (
    FortiOSVariantExhaustedError,
    FortiOSVariantFailure,
    FortiOSVariantOperation,
    FortiOSVariantRegistry,
    SemanticCommandVariant,
    variant_failure_from_parser,
)
from netsage.drivers.fortios.version import FortiOSVersion
from netsage.models import (
    VLAN,
    ArpEntry,
    BGPNeighbor,
    BGPStatus,
    Capability,
    DeviceFacts,
    FirewallPolicy,
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

if TYPE_CHECKING:
    from netsage.drivers.fortios.catalog.execution_models import FortiOSCatalogInvocation


class FortiOSTransport(Protocol):
    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]: ...

    async def execute_semantic(
        self, requests: Sequence[FortiOSRequest | FortiOSSemanticRequest]
    ) -> tuple[str, ...]: ...

    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str: ...


FORTIOS_CAPABILITIES = frozenset(
    {
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

    def __init__(
        self,
        device_id: str,
        transport: FortiOSTransport,
        *,
        variant_registry: FortiOSVariantRegistry | None = None,
    ) -> None:
        self._device_id = device_id
        self._transport = transport
        self._variant_registry = variant_registry or FortiOSVariantRegistry()
        self._facts_cache: DeviceFacts | None = None

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
        facts = parse_device_facts(self._device_id, status)
        self._facts_cache = facts
        return FortiOSSnapshot(
            facts=facts,
            interfaces=tuple(parse_interfaces(self._device_id, config, physical)),
            vlans=tuple(parse_vlans(self._device_id, config)),
            arp_entries=tuple(parse_arp_table(self._device_id, arp)),
            routes=tuple(parse_routes(self._device_id, routes)),
            health=parse_system_health(self._device_id, health),
            firewall_policies=tuple(parse_firewall_policies(self._device_id, policies)),
        )

    async def get_facts(self) -> DeviceFacts:
        if self._facts_cache is not None:
            return self._facts_cache
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))
        facts = parse_device_facts(self._device_id, output)
        self._facts_cache = facts
        return facts

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

    async def get_ha_status(self) -> HAStatus:
        (output,) = await self._transport.execute((FortiOSRequest(FortiOSCommand.HA_STATUS),))
        return parse_ha_status(self._device_id, output)

    async def get_ha_members(self) -> Sequence[HAMember]:
        status = await self.get_ha_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS HA member collection was truncated")
        return status.members

    async def get_sdwan_status(self) -> SDWANStatus:
        members, health = await self._transport.execute_semantic(
            (
                FortiOSRequest(FortiOSCommand.SDWAN_MEMBERS),
                FortiOSSemanticRequest(FortiOSSemanticCommand.SDWAN_HEALTH_CHECKS),
            )
        )
        return parse_sdwan_status(self._device_id, members, health)

    async def get_sdwan_members(self) -> Sequence[SDWANMember]:
        status = await self.get_sdwan_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS SD-WAN member collection was truncated")
        return status.members

    async def get_sdwan_health_checks(self) -> Sequence[SDWANHealthCheck]:
        status = await self.get_sdwan_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS SD-WAN health-check collection was truncated")
        return status.health_checks

    async def get_ipsec_status(self) -> IPsecStatus:
        phase1, tunnels = await self._transport.execute_semantic(
            (
                FortiOSSemanticRequest(FortiOSSemanticCommand.IPSEC_PHASE1),
                FortiOSSemanticRequest(FortiOSSemanticCommand.IPSEC_TUNNELS),
            )
        )
        return parse_ipsec_status(self._device_id, phase1, tunnels)

    async def get_ipsec_tunnels(self) -> Sequence[IPsecTunnel]:
        status = await self.get_ipsec_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS IPsec tunnel collection was truncated")
        return status.tunnels

    async def get_bgp_status(self) -> BGPStatus:
        version = await self._firmware_version()
        candidates = self._variant_registry.candidates(
            FortiOSVariantOperation.BGP_STATUS,
            version,
        )
        attempted: list[str] = []
        for index, variant in enumerate(candidates):
            attempted.append(variant.variant_id)
            try:
                (output,) = await self._transport.execute(variant.requests)
            except FortiOSCommandUnavailableError:
                if self._can_fallback(
                    variant,
                    FortiOSVariantFailure.COMMAND_UNAVAILABLE,
                    index,
                    candidates,
                ):
                    continue
                raise
            try:
                status = (
                    parse_bgp_status(
                        self._device_id,
                        output,
                        variant=variant.parser_variant,
                    )
                    if variant.variant_id == "bgp-summary-v1"
                    else parse_bgp_neighbors_status(
                        self._device_id,
                        output,
                        variant=variant.parser_variant,
                    )
                )
            except FortiOSSemanticParseError as error:
                failure = variant_failure_from_parser(error)
                if failure is not None and self._can_fallback(
                    variant,
                    failure,
                    index,
                    candidates,
                ):
                    continue
                raise FortiOSVariantExhaustedError(
                    error.category,
                    tuple(attempted),
                ) from error
            return status.model_copy(
                update={
                    "parser": status.parser.model_copy(
                        update={"attempted_variants": tuple(attempted)}
                    )
                }
            )
        raise FortiOSVariantExhaustedError(
            FortiOSSemanticErrorCategory.COMMAND_UNAVAILABLE,
            tuple(attempted),
        )

    async def get_bgp_neighbors(self) -> Sequence[BGPNeighbor]:
        status = await self.get_bgp_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS BGP neighbor collection was truncated")
        return status.neighbors

    async def get_ospf_status(self) -> OSPFStatus:
        version = await self._firmware_version()
        candidates = self._variant_registry.candidates(
            FortiOSVariantOperation.OSPF_STATUS,
            version,
        )
        attempted: list[str] = []
        for index, variant in enumerate(candidates):
            attempted.append(variant.variant_id)
            try:
                status_output, neighbors_output = await self._transport.execute(variant.requests)
            except FortiOSCommandUnavailableError:
                if self._can_fallback(
                    variant,
                    FortiOSVariantFailure.COMMAND_UNAVAILABLE,
                    index,
                    candidates,
                ):
                    continue
                raise
            try:
                status = parse_ospf_status(
                    self._device_id,
                    status_output,
                    neighbors_output,
                    variant=variant.parser_variant,
                )
            except FortiOSSemanticParseError as error:
                failure = variant_failure_from_parser(error)
                if failure is not None and self._can_fallback(
                    variant,
                    failure,
                    index,
                    candidates,
                ):
                    continue
                raise FortiOSVariantExhaustedError(
                    error.category,
                    tuple(attempted),
                ) from error
            return status.model_copy(
                update={
                    "parser": status.parser.model_copy(
                        update={"attempted_variants": tuple(attempted)}
                    )
                }
            )
        raise FortiOSVariantExhaustedError(
            FortiOSSemanticErrorCategory.COMMAND_UNAVAILABLE,
            tuple(attempted),
        )

    async def get_ospf_neighbors(self) -> Sequence[OSPFNeighbor]:
        status = await self.get_ospf_status()
        if status.truncated:
            raise IncompleteCollectionError("FortiOS OSPF neighbor collection was truncated")
        return status.neighbors

    async def get_route_summary(self) -> RouteSummary:
        return summarize_routes(self._device_id, await self.get_routes())

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

    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str:
        """Delegate only an ID-based catalog invocation to the trusted transport."""

        return await self._transport.execute_catalog(request)

    async def _firmware_version(self) -> FortiOSVersion:
        facts = await self.get_facts()
        try:
            return FortiOSVersion.parse(
                facts.os_version,
                build=facts.os_build,
                branch_point=facts.branch_point,
                release=facts.release,
            )
        except ValueError as error:
            raise FortiOSSemanticParseError(
                FortiOSSemanticErrorCategory.MALFORMED,
                "FortiOS firmware version is not safely comparable",
            ) from error

    @staticmethod
    def _can_fallback(
        variant: SemanticCommandVariant,
        failure: FortiOSVariantFailure,
        index: int,
        candidates: Sequence[SemanticCommandVariant],
    ) -> bool:
        return failure in variant.fallback_on and index + 1 < len(candidates)
