"""Bounded vendor-neutral models for semantic network observability."""

from enum import StrEnum

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
)

from netsage.models.core import HealthStatus

MAX_HA_MEMBERS = 64
MAX_SDWAN_MEMBERS = 256
MAX_SDWAN_HEALTH_CHECKS = 512
MAX_IPSEC_PHASE1 = 256
MAX_IPSEC_TUNNELS = 256
MAX_IPSEC_PHASE2_PER_TUNNEL = 512
MAX_ROUTING_NEIGHBORS = 512


class HARole(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    MEMBER = "member"
    UNKNOWN = "unknown"


class HASynchronizationState(StrEnum):
    IN_SYNC = "in_sync"
    OUT_OF_SYNC = "out_of_sync"
    UNKNOWN = "unknown"


class HAMember(BaseModel):
    """One HA member; device-controlled identities remain untrusted data."""

    model_config = ConfigDict(frozen=True)

    device_id: str
    member_id: str = Field(min_length=1, max_length=160)
    hostname: str | None = Field(default=None, max_length=255)
    role: HARole = HARole.UNKNOWN
    synchronization: HASynchronizationState = HASynchronizationState.UNKNOWN
    cluster_index: int | None = Field(default=None, ge=0)
    updated_seconds_ago: int | None = Field(default=None, ge=0)
    sessions: int | None = Field(default=None, ge=0)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)


class HAStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    enabled: bool | None = None
    mode: str | None = Field(default=None, max_length=80)
    group_name: str | None = Field(default=None, max_length=255)
    group_id: int | None = Field(default=None, ge=0)
    health: HealthStatus = HealthStatus.UNKNOWN
    cluster_uptime_seconds: int | None = Field(default=None, ge=0)
    primary_member_id: str | None = Field(default=None, max_length=160)
    members: tuple[HAMember, ...] = Field(default=(), max_length=MAX_HA_MEMBERS)
    truncated: bool = False


class SDWANPathState(StrEnum):
    ALIVE = "alive"
    DEAD = "dead"
    DEGRADED = "degraded"
    UNKNOWN = "unknown"


class SDWANSLAState(StrEnum):
    PASSING = "passing"
    FAILING = "failing"
    UNKNOWN = "unknown"


class SDWANMember(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    sequence: int = Field(ge=0)
    interface: str | None = Field(default=None, max_length=255)
    gateway: IPvAnyAddress | None = None
    priority: int | None = Field(default=None, ge=0)
    weight: int | None = Field(default=None, ge=0)


class SDWANHealthCheck(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    name: str = Field(min_length=1, max_length=255)
    member_sequence: int = Field(ge=0)
    interface: str | None = Field(default=None, max_length=255)
    state: SDWANPathState = SDWANPathState.UNKNOWN
    packet_loss_percent: float | None = Field(default=None, ge=0, le=100)
    latency_ms: float | None = Field(default=None, ge=0)
    jitter_ms: float | None = Field(default=None, ge=0)
    sla_state: SDWANSLAState = SDWANSLAState.UNKNOWN
    sla_map: int | None = Field(default=None, ge=0)


class SDWANStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    enabled: bool | None = None
    members: tuple[SDWANMember, ...] = Field(default=(), max_length=MAX_SDWAN_MEMBERS)
    health_checks: tuple[SDWANHealthCheck, ...] = Field(
        default=(), max_length=MAX_SDWAN_HEALTH_CHECKS
    )
    truncated: bool = False


class IPsecPhaseState(StrEnum):
    ESTABLISHED = "established"
    DOWN = "down"
    REKEYING = "rekeying"
    UNKNOWN = "unknown"


class IPsecPhase1(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    name: str = Field(min_length=1, max_length=255)
    peer: IPvAnyAddress | None = None
    interface: str | None = Field(default=None, max_length=255)
    ike_version: int | None = Field(default=None, ge=1, le=2)
    state: IPsecPhaseState = IPsecPhaseState.UNKNOWN
    uptime_seconds: int | None = Field(default=None, ge=0)
    established_sas: int | None = Field(default=None, ge=0)
    created_sas: int | None = Field(default=None, ge=0)
    nat_traversal: bool | None = None
    rekey_seconds: int | None = Field(default=None, ge=0)


class IPsecPhase2(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    name: str = Field(min_length=1, max_length=255)
    state: IPsecPhaseState = IPsecPhaseState.UNKNOWN
    sa_count: int = Field(default=0, ge=0)
    protocol: int | None = Field(default=None, ge=0, le=255)
    source_network: IPvAnyNetwork | None = None
    destination_network: IPvAnyNetwork | None = None
    expires_seconds: int | None = Field(default=None, ge=0)


class IPsecTunnel(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    name: str = Field(min_length=1, max_length=255)
    peer: IPvAnyAddress | None = None
    interface: str | None = Field(default=None, max_length=255)
    ike_version: int | None = Field(default=None, ge=1, le=2)
    phase1_state: IPsecPhaseState = IPsecPhaseState.UNKNOWN
    phase2: tuple[IPsecPhase2, ...] = Field(default=(), max_length=MAX_IPSEC_PHASE2_PER_TUNNEL)
    rx_packets: int | None = Field(default=None, ge=0)
    tx_packets: int | None = Field(default=None, ge=0)
    rx_bytes: int | None = Field(default=None, ge=0)
    tx_bytes: int | None = Field(default=None, ge=0)
    nat_traversal: bool | None = None
    truncated: bool = False


class IPsecStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    enabled: bool | None = None
    phase1: tuple[IPsecPhase1, ...] = Field(default=(), max_length=MAX_IPSEC_PHASE1)
    tunnels: tuple[IPsecTunnel, ...] = Field(default=(), max_length=MAX_IPSEC_TUNNELS)
    truncated: bool = False


class BGPSessionState(StrEnum):
    ESTABLISHED = "established"
    IDLE = "idle"
    CONNECT = "connect"
    ACTIVE = "active"
    OPEN_SENT = "open_sent"
    OPEN_CONFIRM = "open_confirm"
    UNKNOWN = "unknown"


class BGPNeighbor(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    address: IPvAnyAddress
    remote_as: int = Field(ge=0, le=4_294_967_295)
    state: BGPSessionState = BGPSessionState.UNKNOWN
    uptime_seconds: int | None = Field(default=None, ge=0)
    prefixes_received: int | None = Field(default=None, ge=0)
    messages_received: int | None = Field(default=None, ge=0)
    messages_sent: int | None = Field(default=None, ge=0)
    address_family: str | None = Field(default=None, max_length=80)


class BGPStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    enabled: bool | None = None
    router_id: IPvAnyAddress | None = None
    local_as: int | None = Field(default=None, ge=0, le=4_294_967_295)
    table_version: int | None = Field(default=None, ge=0)
    neighbors: tuple[BGPNeighbor, ...] = Field(default=(), max_length=MAX_ROUTING_NEIGHBORS)
    truncated: bool = False


class OSPFNeighborState(StrEnum):
    FULL = "full"
    TWO_WAY = "two_way"
    EXSTART = "exstart"
    EXCHANGE = "exchange"
    LOADING = "loading"
    INIT = "init"
    ATTEMPT = "attempt"
    DOWN = "down"
    UNKNOWN = "unknown"


class OSPFNeighbor(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    neighbor_id: IPvAnyAddress
    address: IPvAnyAddress | None = None
    interface: str | None = Field(default=None, max_length=255)
    state: OSPFNeighborState = OSPFNeighborState.UNKNOWN
    role: str | None = Field(default=None, max_length=40)
    priority: int | None = Field(default=None, ge=0)
    dead_time_seconds: int | None = Field(default=None, ge=0)
    area: str | None = Field(default=None, max_length=80)


class OSPFStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    enabled: bool | None = None
    process_id: int | None = Field(default=None, ge=0)
    router_id: IPvAnyAddress | None = None
    neighbors: tuple[OSPFNeighbor, ...] = Field(default=(), max_length=MAX_ROUTING_NEIGHBORS)
    truncated: bool = False


class RouteSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    total_routes: int = Field(ge=0)
    active_routes: int = Field(ge=0)
    default_routes: int = Field(ge=0)
    active_default_routes: int = Field(ge=0)
    equal_cost_default_routes: bool = False
    protocols: tuple[str, ...] = Field(default=(), max_length=128)
