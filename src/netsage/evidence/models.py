"""Typed, immutable evidence snapshots built from normalized broker results."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsage.models import (
    VLAN,
    ArpEntry,
    BGPNeighbor,
    BGPStatus,
    Capability,
    DataTrust,
    DeviceFacts,
    FirewallPolicy,
    HAMember,
    HAStatus,
    Interface,
    IPsecStatus,
    IPsecTunnel,
    OSPFNeighbor,
    OSPFStatus,
    PingResult,
    Platform,
    Route,
    RouteSummary,
    SDWANHealthCheck,
    SDWANMember,
    SDWANStatus,
    SystemHealth,
    TracerouteResult,
)
from netsage.models.observability import (
    MAX_HA_MEMBERS,
    MAX_IPSEC_TUNNELS,
    MAX_ROUTING_NEIGHBORS,
    MAX_SDWAN_HEALTH_CHECKS,
    MAX_SDWAN_MEMBERS,
)


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


class EvidenceProvenance(BaseModel):
    """Non-secret collection metadata for one structured observation."""

    model_config = ConfigDict(frozen=True)

    tool: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    device_id: str = Field(min_length=1)
    capability: Capability
    platform: Platform
    driver: str = Field(min_length=1, max_length=128)
    collection_method: Literal["structured_broker_tool"] = "structured_broker_tool"


class DeviceFactsEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["device_facts"] = "device_facts"
    facts: DeviceFacts


class InterfacesEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["interfaces"] = "interfaces"
    interfaces: tuple[Interface, ...]


class VlansEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["vlans"] = "vlans"
    vlans: tuple[VLAN, ...]


class ArpEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["arp_entries"] = "arp_entries"
    entries: tuple[ArpEntry, ...]


class RoutesEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["routes"] = "routes"
    routes: tuple[Route, ...]


class SystemHealthEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["system_health"] = "system_health"
    health: SystemHealth


class FirewallPoliciesEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["firewall_policies"] = "firewall_policies"
    policies: tuple[FirewallPolicy, ...]


class PingEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ping"] = "ping"
    result: PingResult


class TracerouteEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["traceroute"] = "traceroute"
    result: TracerouteResult


class HAStatusEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ha_status"] = "ha_status"
    status: HAStatus


class HAMembersEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ha_members"] = "ha_members"
    members: tuple[HAMember, ...] = Field(max_length=MAX_HA_MEMBERS)


class SDWANStatusEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["sdwan_status"] = "sdwan_status"
    status: SDWANStatus


class SDWANMembersEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["sdwan_members"] = "sdwan_members"
    members: tuple[SDWANMember, ...] = Field(max_length=MAX_SDWAN_MEMBERS)


class SDWANHealthChecksEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["sdwan_health_checks"] = "sdwan_health_checks"
    health_checks: tuple[SDWANHealthCheck, ...] = Field(max_length=MAX_SDWAN_HEALTH_CHECKS)


class IPsecStatusEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ipsec_status"] = "ipsec_status"
    status: IPsecStatus


class IPsecTunnelsEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ipsec_tunnels"] = "ipsec_tunnels"
    tunnels: tuple[IPsecTunnel, ...] = Field(max_length=MAX_IPSEC_TUNNELS)


class BGPStatusEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["bgp_status"] = "bgp_status"
    status: BGPStatus


class BGPNeighborsEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["bgp_neighbors"] = "bgp_neighbors"
    neighbors: tuple[BGPNeighbor, ...] = Field(max_length=MAX_ROUTING_NEIGHBORS)


class OSPFStatusEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ospf_status"] = "ospf_status"
    status: OSPFStatus


class OSPFNeighborsEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["ospf_neighbors"] = "ospf_neighbors"
    neighbors: tuple[OSPFNeighbor, ...] = Field(max_length=MAX_ROUTING_NEIGHBORS)


class RouteSummaryEvidencePayload(BaseModel):
    model_config = ConfigDict(frozen=True)

    kind: Literal["route_summary"] = "route_summary"
    summary: RouteSummary


EvidencePayload = Annotated[
    DeviceFactsEvidencePayload
    | InterfacesEvidencePayload
    | VlansEvidencePayload
    | ArpEvidencePayload
    | RoutesEvidencePayload
    | SystemHealthEvidencePayload
    | FirewallPoliciesEvidencePayload
    | PingEvidencePayload
    | TracerouteEvidencePayload
    | HAStatusEvidencePayload
    | HAMembersEvidencePayload
    | SDWANStatusEvidencePayload
    | SDWANMembersEvidencePayload
    | SDWANHealthChecksEvidencePayload
    | IPsecStatusEvidencePayload
    | IPsecTunnelsEvidencePayload
    | BGPStatusEvidencePayload
    | BGPNeighborsEvidencePayload
    | OSPFStatusEvidencePayload
    | OSPFNeighborsEvidencePayload
    | RouteSummaryEvidencePayload,
    Field(discriminator="kind"),
]


def _payload_capability(payload: EvidencePayload) -> Capability:
    if isinstance(payload, DeviceFactsEvidencePayload):
        return Capability.FACTS
    if isinstance(payload, InterfacesEvidencePayload):
        return Capability.INTERFACES
    if isinstance(payload, VlansEvidencePayload):
        return Capability.VLANS
    if isinstance(payload, ArpEvidencePayload):
        return Capability.ARP
    if isinstance(payload, RoutesEvidencePayload):
        return Capability.ROUTES
    if isinstance(payload, SystemHealthEvidencePayload):
        return Capability.SYSTEM_HEALTH
    if isinstance(payload, FirewallPoliciesEvidencePayload):
        return Capability.FIREWALL
    if isinstance(payload, PingEvidencePayload):
        return Capability.PING
    if isinstance(payload, TracerouteEvidencePayload):
        return Capability.TRACEROUTE
    if isinstance(payload, HAStatusEvidencePayload | HAMembersEvidencePayload):
        return Capability.HA
    if isinstance(
        payload,
        SDWANStatusEvidencePayload | SDWANMembersEvidencePayload | SDWANHealthChecksEvidencePayload,
    ):
        return Capability.SDWAN
    if isinstance(payload, IPsecStatusEvidencePayload | IPsecTunnelsEvidencePayload):
        return Capability.IPSEC
    if isinstance(payload, BGPStatusEvidencePayload | BGPNeighborsEvidencePayload):
        return Capability.BGP
    if isinstance(payload, OSPFStatusEvidencePayload | OSPFNeighborsEvidencePayload):
        return Capability.OSPF
    return Capability.ROUTES


def _payload_device_ids(payload: EvidencePayload) -> frozenset[str]:
    if isinstance(payload, DeviceFactsEvidencePayload):
        return frozenset({payload.facts.device_id})
    if isinstance(payload, InterfacesEvidencePayload):
        return frozenset(item.device_id for item in payload.interfaces)
    if isinstance(payload, VlansEvidencePayload):
        return frozenset(item.device_id for item in payload.vlans)
    if isinstance(payload, ArpEvidencePayload):
        return frozenset(item.device_id for item in payload.entries)
    if isinstance(payload, RoutesEvidencePayload):
        return frozenset(item.device_id for item in payload.routes)
    if isinstance(payload, SystemHealthEvidencePayload):
        return frozenset({payload.health.device_id})
    if isinstance(payload, FirewallPoliciesEvidencePayload):
        return frozenset(item.device_id for item in payload.policies)
    if isinstance(payload, PingEvidencePayload):
        return frozenset({payload.result.device_id})
    if isinstance(payload, TracerouteEvidencePayload):
        return frozenset({payload.result.device_id})
    if isinstance(payload, HAStatusEvidencePayload):
        return frozenset({payload.status.device_id})
    if isinstance(payload, HAMembersEvidencePayload):
        return frozenset(item.device_id for item in payload.members)
    if isinstance(payload, SDWANStatusEvidencePayload):
        return frozenset({payload.status.device_id})
    if isinstance(payload, SDWANMembersEvidencePayload):
        return frozenset(item.device_id for item in payload.members)
    if isinstance(payload, SDWANHealthChecksEvidencePayload):
        return frozenset(item.device_id for item in payload.health_checks)
    if isinstance(payload, IPsecStatusEvidencePayload):
        return frozenset({payload.status.device_id})
    if isinstance(payload, IPsecTunnelsEvidencePayload):
        return frozenset(item.device_id for item in payload.tunnels)
    if isinstance(payload, BGPStatusEvidencePayload):
        return frozenset({payload.status.device_id})
    if isinstance(payload, BGPNeighborsEvidencePayload):
        return frozenset(item.device_id for item in payload.neighbors)
    if isinstance(payload, OSPFStatusEvidencePayload):
        return frozenset({payload.status.device_id})
    if isinstance(payload, OSPFNeighborsEvidencePayload):
        return frozenset(item.device_id for item in payload.neighbors)
    return frozenset({payload.summary.device_id})


class EvidenceEnvelope(BaseModel):
    """A point-in-time, normalized observation with explicit trust and provenance."""

    model_config = ConfigDict(frozen=True)

    evidence_id: UUID
    investigation_id: UUID
    device_id: str = Field(min_length=1)
    operation: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    capability: Capability
    observed_at: datetime
    trust: DataTrust
    payload: EvidencePayload
    provenance: EvidenceProvenance

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.trust is not DataTrust.UNTRUSTED_DEVICE_DATA:
            raise ValueError("device evidence must remain untrusted device data")
        if self.provenance.tool != self.operation:
            raise ValueError("provenance tool must match evidence operation")
        if self.provenance.device_id != self.device_id:
            raise ValueError("provenance device must match evidence device")
        if self.provenance.capability is not self.capability:
            raise ValueError("provenance capability must match evidence capability")
        if _payload_capability(self.payload) is not self.capability:
            raise ValueError("payload type must match evidence capability")
        payload_device_ids = _payload_device_ids(self.payload)
        if payload_device_ids and payload_device_ids != {self.device_id}:
            raise ValueError("payload device identity must match evidence device")
        return self


class EvidenceFailurePhase(StrEnum):
    BROKER = "broker"
    NORMALIZATION = "normalization"
    STORAGE = "storage"


class EvidenceCollectionFailure(BaseModel):
    """Safe missing-evidence metadata which never embeds a raw exception message."""

    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    device_id: str = Field(min_length=1)
    operation: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    capability: Capability
    observed_at: datetime
    phase: EvidenceFailurePhase
    error_type: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]*$")
    reason: str = Field(min_length=1, max_length=160)

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)
