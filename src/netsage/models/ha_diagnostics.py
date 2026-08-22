"""Bounded vendor-neutral models for deterministic HA diagnostics."""

from datetime import datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

from netsage.models.observability import HARole, SemanticParserMetadata

MAX_HA_HISTORY_EVENTS = 2_048
MAX_HA_CHECKSUM_SCOPES = 128
MAX_HA_INCIDENT_EPISODES = 512


class HATimestampKind(StrEnum):
    OFFSET_AWARE = "offset_aware"
    DEVICE_LOCAL = "device_local"
    UNKNOWN = "unknown"


class HATimelineOrdering(StrEnum):
    TIMESTAMP = "timestamp"
    SOURCE_ORDER = "source_order"
    UNCERTAIN = "uncertain"


class HAEventState(StrEnum):
    UP = "up"
    DOWN = "down"
    IN_SYNC = "in_sync"
    OUT_OF_SYNC = "out_of_sync"
    UNKNOWN = "unknown"


class HAEventType(StrEnum):
    HEARTBEAT_LOST = "heartbeat_lost"
    HEARTBEAT_RESTORED = "heartbeat_restored"
    HEARTBEAT_INTERFACE_DOWN = "heartbeat_interface_down"
    HEARTBEAT_INTERFACE_RESTORED = "heartbeat_interface_restored"
    HEARTBEAT_INTERFACE_STATE_CHANGED = "heartbeat_interface_state_changed"
    MEMBER_LEFT = "member_left"
    MEMBER_JOINED = "member_joined"
    MEMBER_REJOINED = "member_rejoined"
    ROLE_CHANGED = "role_changed"
    PRIMARY_CHANGED = "primary_changed"
    FAILOVER = "failover"
    MEMBER_RESTARTED = "member_restarted"
    MEMBER_BOOTED = "member_booted"
    HA_PROCESS_RESTARTED = "ha_process_restarted"
    SYNC_LOST = "sync_lost"
    SYNC_RESTORED = "sync_restored"
    UNKNOWN = "unknown"


class HAEvent(BaseModel):
    """One normalized HA event without raw history text or device identity."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Field(min_length=1)
    source_index: int = Field(ge=0)
    timestamp: datetime | None = None
    timestamp_kind: HATimestampKind = HATimestampKind.UNKNOWN
    event_type: HAEventType
    member_ref: str | None = Field(default=None, pattern=r"^member-[1-9][0-9]*$")
    role: HARole = HARole.UNKNOWN
    heartbeat_interface: str | None = Field(default=None, min_length=1, max_length=128)
    previous_state: HAEventState = HAEventState.UNKNOWN
    new_state: HAEventState = HAEventState.UNKNOWN

    @model_validator(mode="after")
    def validate_timestamp(self) -> Self:
        if self.timestamp is None and self.timestamp_kind is not HATimestampKind.UNKNOWN:
            raise ValueError("timestamp kind requires a timestamp")
        if self.timestamp is not None and self.timestamp_kind is HATimestampKind.UNKNOWN:
            raise ValueError("timestamp requires an explicit timestamp kind")
        if self.timestamp is not None:
            aware = self.timestamp.tzinfo is not None and self.timestamp.utcoffset() is not None
            if aware != (self.timestamp_kind is HATimestampKind.OFFSET_AWARE):
                raise ValueError("timestamp awareness does not match timestamp kind")
        return self


class HAHistory(BaseModel):
    """Normalized bounded HA history; raw diagnostic lines are deliberately absent."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Field(min_length=1)
    parser: SemanticParserMetadata
    events: tuple[HAEvent, ...] = Field(max_length=MAX_HA_HISTORY_EVENTS)
    ordering: HATimelineOrdering
    source_line_count: int = Field(ge=0)
    unrecognized_event_count: int = Field(ge=0)
    duplicate_event_count: int = Field(ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def validate_events(self) -> Self:
        if any(event.device_id != self.device_id for event in self.events):
            raise ValueError("HA history event device identity mismatch")
        if self.unrecognized_event_count != sum(
            event.event_type is HAEventType.UNKNOWN for event in self.events
        ):
            raise ValueError("unrecognized HA event count is inconsistent")
        return self


class HAChecksumScope(StrEnum):
    GLOBAL = "global"
    VDOM = "vdom"
    ALL = "all"
    UNKNOWN = "unknown"


class HAChecksumScopeResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: HAChecksumScope
    compared_values: int = Field(ge=1)
    distinct_values: int = Field(ge=1)
    synchronized: bool | None = None

    @model_validator(mode="after")
    def validate_comparison(self) -> Self:
        if self.distinct_values > self.compared_values:
            raise ValueError("distinct checksum count exceeds compared count")
        expected = None if self.compared_values < 2 else self.distinct_values == 1
        if self.synchronized is not expected:
            raise ValueError("checksum synchronization state is inconsistent")
        return self


class HAChecksumMismatch(BaseModel):
    """A mismatch category without configuration values or checksum fingerprints."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    scope: HAChecksumScope
    category: str = Field(pattern=r"^(global|vdom|all|unknown)$")
    compared_values: int = Field(ge=2)
    distinct_values: int = Field(ge=2)


class HAChecksumStatus(BaseModel):
    """Comparison-only HA checksum evidence; no configuration content is retained."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Field(min_length=1)
    parser: SemanticParserMetadata
    synchronized: bool | None = None
    scopes: tuple[HAChecksumScopeResult, ...] = Field(max_length=MAX_HA_CHECKSUM_SCOPES)
    mismatches: tuple[HAChecksumMismatch, ...] = Field(max_length=MAX_HA_CHECKSUM_SCOPES)
    mismatch_count: int = Field(ge=0)
    source_line_count: int = Field(ge=0)
    truncated: bool = False

    @model_validator(mode="after")
    def validate_status(self) -> Self:
        if self.mismatch_count != len(self.mismatches):
            raise ValueError("checksum mismatch count is inconsistent")
        comparable = tuple(item for item in self.scopes if item.synchronized is not None)
        expected = (
            None if not comparable else not any(item.synchronized is False for item in comparable)
        )
        if self.synchronized is not expected:
            raise ValueError("overall checksum synchronization state is inconsistent")
        return self


class HAFaultDomain(StrEnum):
    CONFIGURATION_SYNCHRONIZATION = "configuration_synchronization"
    HA_HEARTBEAT_COMMUNICATION = "ha_heartbeat_communication"
    HA_HEARTBEAT_INTERFACE = "ha_heartbeat_interface"
    MEMBER_RESTART = "member_restart"
    HA_PROCESS = "ha_process"
    CLUSTER_MEMBERSHIP = "cluster_membership"
    UNKNOWN = "unknown"


class HAObservedPattern(StrEnum):
    CONFIGURATION_DRIFT = "configuration_drift"
    HEARTBEAT_COMMUNICATION_INSTABILITY = "heartbeat_communication_instability"
    HEARTBEAT_INTERFACE_INSTABILITY = "heartbeat_interface_instability"
    HEARTBEAT_INTERFACE_UNAVAILABLE = "heartbeat_interface_unavailable"
    CLUSTER_MEMBERSHIP_INSTABILITY = "cluster_membership_instability"
    MEMBER_RESTART = "member_restart"
    HA_PROCESS_RESTART = "ha_process_restart"
    REPEATED_INSTABILITY = "repeated_instability"


class HAIncidentEpisode(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    episode_index: int = Field(ge=1)
    event_indices: tuple[int, ...] = Field(min_length=1, max_length=MAX_HA_HISTORY_EVENTS)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    event_types: tuple[HAEventType, ...]
    member_refs: tuple[str, ...] = ()
    heartbeat_interfaces: tuple[str, ...] = ()


class HATimeline(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    events: tuple[HAEvent, ...] = Field(max_length=MAX_HA_HISTORY_EVENTS)
    ordering: HATimelineOrdering
    duplicates_removed: int = Field(ge=0)
    truncated: bool = False


class HACorrelationResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    timeline: HATimeline
    episodes: tuple[HAIncidentEpisode, ...] = Field(max_length=MAX_HA_INCIDENT_EPISODES)
    observed_patterns: tuple[HAObservedPattern, ...]
    fault_domains: tuple[HAFaultDomain, ...]
    heartbeat_interfaces: tuple[str, ...] = ()
    matched_interface_count: int = Field(ge=0)
    missing_evidence: tuple[str, ...] = ()
    specific_physical_cause_confirmed: Literal[False] = False
