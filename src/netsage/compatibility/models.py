"""Typed, non-secret device compatibility reports."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsage.drivers.fortios import FortiOSVersion
from netsage.models import Capability, Platform

COMPATIBILITY_REPORT_SCHEMA_VERSION = 1


class CompatibilityArea(StrEnum):
    SYSTEM = "system"
    INTERFACES = "interfaces"
    ROUTING = "routing"
    FIREWALL = "firewall"
    HA = "ha"
    SDWAN = "sdwan"
    IPSEC = "ipsec"
    BGP = "bgp"
    OSPF = "ospf"


class CapabilityObservationState(StrEnum):
    SUPPORTED = "supported"
    ENABLED = "enabled"
    DISABLED = "disabled"
    NOT_CONFIGURED = "not_configured"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    OUTPUT_UNRECOGNIZED = "output_unrecognized"
    PARTIAL = "partial"


class CompatibilityParserState(StrEnum):
    PARSED = "parsed"
    PARTIAL = "partial"
    UNRECOGNIZED = "unrecognized"
    NOT_APPLICABLE = "not_applicable"


class CompatibilityErrorCategory(StrEnum):
    NONE = "none"
    CREDENTIAL_UNAVAILABLE = "credential_unavailable"
    AUTHENTICATION_FAILED = "authentication_failed"
    HOST_KEY_FAILED = "host_key_failed"
    TRANSPORT_FAILED = "transport_failed"
    TIMEOUT = "timeout"
    OUTPUT_LIMIT = "output_limit"
    PERMISSION_DENIED = "permission_denied"
    COMMAND_UNAVAILABLE = "command_unavailable"
    EMPTY_OUTPUT = "empty_output"
    OUTPUT_UNRECOGNIZED = "output_unrecognized"
    PARTIAL = "partial"


class FortiOSVDOMMode(StrEnum):
    SINGLE = "single"
    MULTI = "multi"
    UNKNOWN = "unknown"


class FortiOSVDOMContext(StrEnum):
    GLOBAL = "global"
    ROOT = "root"
    SPECIFIC = "specific"
    UNKNOWN = "unknown"


class FortiOSVDOMProfile(BaseModel):
    """Context category only; no VDOM name is retained."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: FortiOSVDOMMode = FortiOSVDOMMode.UNKNOWN
    context: FortiOSVDOMContext = FortiOSVDOMContext.UNKNOWN
    maximum: int | None = Field(default=None, ge=0)


class CompatibilityAreaResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    area: CompatibilityArea
    operations: tuple[str, ...] = Field(min_length=1, max_length=3)
    capabilities: tuple[Capability, ...] = Field(min_length=1, max_length=3)
    state: CapabilityObservationState
    parser_state: CompatibilityParserState
    parser_variants: tuple[str, ...] = Field(default=(), max_length=3)
    error_category: CompatibilityErrorCategory = CompatibilityErrorCategory.NONE

    @field_validator("operations")
    @classmethod
    def validate_operations(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        for value in values:
            if not value or not value.replace("_", "").isalnum():
                raise ValueError("compatibility operation name is invalid")
        return values


class FortiOSCompatibilityReport(BaseModel):
    """Safe operational metadata; never contains raw output or network addresses."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    netsage_version: str = Field(min_length=1, max_length=40)
    generated_at: datetime
    device_id: str = Field(min_length=1, max_length=128)
    anonymized: bool = False
    platform: Literal[Platform.FORTIOS] = Platform.FORTIOS
    firmware: FortiOSVersion | None = None
    model_family: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$",
    )
    vdom: FortiOSVDOMProfile = Field(default_factory=FortiOSVDOMProfile)
    areas: tuple[CompatibilityAreaResult, ...] = Field(min_length=9, max_length=9)
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    configuration_changed: Literal[False] = False
    raw_cli_included: Literal[False] = False
    credentials_included: Literal[False] = False

    @field_validator("generated_at")
    @classmethod
    def validate_generated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("compatibility report timestamp must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_area_coverage(self) -> Self:
        if {result.area for result in self.areas} != set(CompatibilityArea):
            raise ValueError("compatibility report must contain every core area once")
        return self

    def anonymized_copy(self) -> Self:
        return self.model_copy(update={"device_id": "fortios-device", "anonymized": True})
