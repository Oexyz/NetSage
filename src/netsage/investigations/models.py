"""Vendor-neutral deterministic investigation, finding, and diagnosis models."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsage.evidence import EvidenceCollectionFailure
from netsage.models import HAFaultDomain, HASynchronizationState


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    return value.astimezone(UTC)


class DiagnosisStrength(StrEnum):
    CONFIRMED = "confirmed"
    STRONG = "strong"
    PROBABLE = "probable"
    INSUFFICIENT = "insufficient"


class FindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class InvestigationStatus(StrEnum):
    HEALTHY = "healthy"
    WARNING = "warning"
    CRITICAL = "critical"
    INSUFFICIENT = "insufficient"


class InvestigationKind(StrEnum):
    FORTIGATE_HEALTH = "fortigate_health"
    DEFAULT_ROUTE = "default_route"
    INTERFACE_STATE = "interface_state"
    HA_HEALTH = "ha_health"
    SDWAN_HEALTH = "sdwan_health"
    IPSEC_HEALTH = "ipsec_health"
    DYNAMIC_ROUTING_HEALTH = "dynamic_routing_health"


class FortiOSInvestigationFocus(StrEnum):
    HEALTH = "health"
    HA = "ha"
    SDWAN = "sdwan"
    IPSEC = "ipsec"
    ROUTING = "routing"


class Investigation(BaseModel):
    """Immutable identity and scope for one deterministic workflow run."""

    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    device_id: str = Field(min_length=1)
    kind: InvestigationKind
    started_at: datetime
    target_interface: str | None = None

    @field_validator("started_at")
    @classmethod
    def validate_started_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.kind is InvestigationKind.INTERFACE_STATE and not self.target_interface:
            raise ValueError("interface-state investigation requires a target interface")
        if self.kind is not InvestigationKind.INTERFACE_STATE and self.target_interface is not None:
            raise ValueError("target interface is valid only for interface-state investigations")
        return self


class Finding(BaseModel):
    """An observed condition, which is not automatically a root-cause diagnosis."""

    model_config = ConfigDict(frozen=True)

    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    title: str = Field(min_length=1, max_length=160)
    summary: str = Field(min_length=1, max_length=500)
    severity: FindingSeverity
    strength: DiagnosisStrength | None = None
    evidence_ids: tuple[UUID, ...]


class Diagnosis(BaseModel):
    """An optional deterministic conclusion referencing evidence by identifier."""

    model_config = ConfigDict(frozen=True)

    summary: str = Field(min_length=1, max_length=500)
    strength: DiagnosisStrength
    evidence_ids: tuple[UUID, ...] = ()
    missing_evidence: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_strength(self) -> Self:
        if self.strength is not DiagnosisStrength.INSUFFICIENT and not self.evidence_ids:
            raise ValueError("supported diagnosis must reference evidence")
        return self


class HADiagnosticSummary(BaseModel):
    """Typed presentation of deterministic HA correlation, not a second diagnosis engine."""

    model_config = ConfigDict(frozen=True)

    synchronization: HASynchronizationState
    history_event_count: int = Field(ge=0)
    incident_count: int = Field(ge=0)
    heartbeat_instability: bool
    interface_instability: bool
    checksum_mismatch_count: int = Field(ge=0)
    member_restart_observed: bool
    ha_process_restart_observed: bool
    fault_domains: tuple[HAFaultDomain, ...]
    strength: DiagnosisStrength
    missing_evidence: tuple[str, ...] = ()
    specific_physical_cause_confirmed: Literal[False] = False


class InvestigationReport(BaseModel):
    """Structured report with separate evidence references, findings, and diagnosis."""

    model_config = ConfigDict(frozen=True)

    investigation: Investigation
    completed_at: datetime
    status: InvestigationStatus
    evidence_ids: tuple[UUID, ...]
    failures: tuple[EvidenceCollectionFailure, ...] = ()
    findings: tuple[Finding, ...] = ()
    diagnosis: Diagnosis | None = None
    ha_summary: HADiagnosticSummary | None = None
    configuration_changed: Literal[False] = False

    @field_validator("completed_at")
    @classmethod
    def validate_completed_at(cls, value: datetime) -> datetime:
        return _utc_datetime(value)

    @model_validator(mode="after")
    def validate_references(self) -> Self:
        if self.completed_at < self.investigation.started_at:
            raise ValueError("report cannot complete before investigation starts")
        evidence_ids = set(self.evidence_ids)
        for finding in self.findings:
            if not set(finding.evidence_ids).issubset(evidence_ids):
                raise ValueError("finding references evidence outside the investigation")
        if self.diagnosis and not set(self.diagnosis.evidence_ids).issubset(evidence_ids):
            raise ValueError("diagnosis references evidence outside the investigation")
        if (
            self.ha_summary is not None
            and self.investigation.kind is not InvestigationKind.HA_HEALTH
        ):
            raise ValueError("HA diagnostic summary requires an HA investigation")
        if self.failures and self.status is not InvestigationStatus.INSUFFICIENT:
            raise ValueError("partial collection must be reported as insufficient")
        return self
