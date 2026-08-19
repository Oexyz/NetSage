"""Vendor-neutral, non-secret core models."""

from enum import StrEnum
from re import compile as compile_pattern
from typing import Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    IPvAnyNetwork,
    JsonValue,
    RootModel,
    field_validator,
    model_validator,
)

_REFERENCE_PATTERN = compile_pattern(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_MAC_PATTERN = compile_pattern(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")


class Capability(StrEnum):
    """A concrete operation family implemented by a device driver."""

    FACTS = "facts"
    INTERFACES = "interfaces"
    VLANS = "vlans"
    MAC_TABLE = "mac_table"
    ARP = "arp"
    ROUTES = "routes"
    LLDP = "lldp"
    SYSTEM_HEALTH = "system_health"
    FIREWALL = "firewall"
    VPN = "vpn"
    BGP = "bgp"
    OSPF = "ospf"
    LOGS = "logs"
    PING = "ping"
    TRACEROUTE = "traceroute"


class Platform(StrEnum):
    """Platforms intentionally recognized by the current inventory schema."""

    FORTIOS = "fortios"
    FORTISWITCH = "fortiswitch"
    ARUBA_AOSS = "aruba_aoss"
    ARUBA_AOSCX = "aruba_aoscx"


class InterfaceState(StrEnum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class HealthStatus(StrEnum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class DataTrust(StrEnum):
    """How downstream consumers must interpret a result payload."""

    UNTRUSTED_DEVICE_DATA = "untrusted_device_data"


class CredentialReference(RootModel[str]):
    """Opaque lookup key; this model never contains credential material."""

    model_config = ConfigDict(frozen=True)

    @field_validator("root")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        if not _REFERENCE_PATTERN.fullmatch(value):
            raise ValueError("credential reference must be an opaque name")
        return value

    def __str__(self) -> str:
        return self.root


class DeviceRef(BaseModel):
    """Non-secret inventory reference to a managed device."""

    model_config = ConfigDict(frozen=True)

    name: str
    host: str
    platform: Platform
    credential_ref: CredentialReference
    site: str | None = None
    groups: frozenset[str] = frozenset()
    capabilities: frozenset[Capability] = frozenset()
    tags: frozenset[str] = frozenset()
    metadata: dict[str, JsonValue] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_safe_identity(self) -> Self:
        for label, value in (("device name", self.name), ("host", self.host)):
            if not value.strip():
                raise ValueError(f"{label} must not be blank")
        if "@" in self.host:
            raise ValueError("host must not contain embedded credentials")
        return self


class DeviceFacts(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    vendor: str
    model: str
    os_version: str
    hostname: str | None = None


class InterfaceErrors(BaseModel):
    model_config = ConfigDict(frozen=True)

    crc: int = Field(default=0, ge=0)
    rx: int = Field(default=0, ge=0)
    tx: int = Field(default=0, ge=0)


class Interface(BaseModel):
    """Normalized interface state; descriptions remain untrusted device data."""

    model_config = ConfigDict(frozen=True)

    device_id: str
    name: str
    admin_state: InterfaceState
    operational_state: InterfaceState
    description: str | None = None
    speed_mbps: int | None = Field(default=None, gt=0)
    mtu: int | None = Field(default=None, ge=576)
    vlans: tuple[int, ...] = ()
    errors: InterfaceErrors = Field(default_factory=InterfaceErrors)

    @field_validator("vlans")
    @classmethod
    def validate_vlans(cls, values: tuple[int, ...]) -> tuple[int, ...]:
        if any(vlan < 1 or vlan > 4094 for vlan in values):
            raise ValueError("VLAN IDs must be between 1 and 4094")
        return values


class VLAN(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    vlan_id: int = Field(ge=1, le=4094)
    name: str | None = None


class MacEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    mac_address: str
    vlan_id: int = Field(ge=1, le=4094)
    interface: str

    @field_validator("mac_address")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        normalized = value.lower().replace("-", ":")
        if not _MAC_PATTERN.fullmatch(normalized):
            raise ValueError("invalid MAC address")
        return normalized


class ArpEntry(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    ip_address: IPvAnyAddress
    mac_address: str
    interface: str | None = None

    @field_validator("mac_address")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        return MacEntry.normalize_mac(value)


class Route(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    prefix: IPvAnyNetwork
    protocol: str
    next_hop: IPvAnyAddress | None = None
    interface: str | None = None
    metric: int | None = Field(default=None, ge=0)


class LldpNeighbor(BaseModel):
    """Normalized LLDP data; all remote-provided strings are untrusted."""

    model_config = ConfigDict(frozen=True)

    device_id: str
    local_interface: str
    remote_device: str
    remote_interface: str | None = None
    management_address: IPvAnyAddress | None = None


class SystemHealth(BaseModel):
    model_config = ConfigDict(frozen=True)

    device_id: str
    status: HealthStatus
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    memory_percent: float | None = Field(default=None, ge=0, le=100)
    observations: tuple[str, ...] = ()


class CommandResult(BaseModel):
    """Sanitized output returned by a read-only driver operation."""

    model_config = ConfigDict(frozen=True)

    device: str
    operation: str
    output: dict[str, JsonValue]
    content_trust: DataTrust = DataTrust.UNTRUSTED_DEVICE_DATA
