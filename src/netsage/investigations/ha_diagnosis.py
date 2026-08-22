"""Build deterministic HA findings from typed status and correlation evidence."""

from dataclasses import dataclass
from uuid import UUID

from netsage.investigations.models import (
    Diagnosis,
    DiagnosisStrength,
    Finding,
    FindingSeverity,
    HADiagnosticSummary,
)
from netsage.models import (
    HAChecksumStatus,
    HACorrelationResult,
    HAFaultDomain,
    HAHistory,
    HAObservedPattern,
    HAStatus,
    HASynchronizationState,
    HealthStatus,
    Interface,
    InterfaceState,
)


@dataclass(frozen=True, slots=True)
class HAAssessment:
    findings: tuple[Finding, ...]
    diagnosis: Diagnosis | None
    summary: HADiagnosticSummary


def build_ha_assessment(
    *,
    status: HAStatus,
    status_evidence_id: UUID,
    history: HAHistory | None = None,
    history_evidence_id: UUID | None = None,
    checksum: HAChecksumStatus | None = None,
    checksum_evidence_id: UUID | None = None,
    interfaces: tuple[Interface, ...] = (),
    interface_evidence_id: UUID | None = None,
    correlation: HACorrelationResult | None = None,
    missing_evidence: tuple[str, ...] = (),
) -> HAAssessment:
    findings: list[Finding] = []
    out_of_sync = tuple(
        member
        for member in status.members
        if member.synchronization is HASynchronizationState.OUT_OF_SYNC
    )
    synchronization = _synchronization(status)
    status_ids: tuple[UUID, ...] = (status_evidence_id,)

    if status.enabled is False:
        findings.append(
            _finding(
                "ha_disabled",
                "HA disabled",
                "FortiOS reports that HA is not enabled.",
                FindingSeverity.INFO,
                DiagnosisStrength.CONFIRMED,
                status_ids,
            )
        )
    elif out_of_sync:
        evidence_ids: tuple[UUID, ...] = status_ids
        if checksum is not None and checksum.mismatch_count and checksum_evidence_id is not None:
            evidence_ids += (checksum_evidence_id,)
        findings.append(
            _finding(
                "ha_configuration_out_of_sync",
                "HA configuration out of sync",
                f"FortiOS reports {len(out_of_sync)} HA member(s) out of sync.",
                FindingSeverity.WARNING,
                DiagnosisStrength.CONFIRMED,
                evidence_ids,
            )
        )
    elif status.health in {HealthStatus.DEGRADED, HealthStatus.UNHEALTHY}:
        findings.append(
            _finding(
                "ha_health_degraded",
                "HA health degraded",
                f"FortiOS reports HA health as {status.health.value}.",
                (
                    FindingSeverity.CRITICAL
                    if status.health is HealthStatus.UNHEALTHY
                    else FindingSeverity.WARNING
                ),
                DiagnosisStrength.CONFIRMED,
                status_ids,
            )
        )
    elif status.enabled and status.members:
        findings.append(
            _finding(
                "ha_cluster_healthy",
                "HA cluster healthy",
                "Observed HA members are synchronized and HA health is not degraded.",
                FindingSeverity.INFO,
                DiagnosisStrength.CONFIRMED,
                status_ids,
            )
        )
    if status.enabled and len(status.members) < 2:
        findings.append(
            _finding(
                "ha_member_count_low",
                "Fewer than two HA members observed",
                "Only one HA member was observed; expected membership is not known.",
                FindingSeverity.WARNING,
                DiagnosisStrength.PROBABLE,
                status_ids,
            )
        )

    if checksum is not None and checksum.mismatch_count and checksum_evidence_id is not None:
        findings.append(
            _finding(
                "ha_checksum_mismatch",
                "HA checksum mismatch",
                f"FortiOS reports {checksum.mismatch_count} non-synchronized checksum scope(s).",
                FindingSeverity.WARNING,
                DiagnosisStrength.CONFIRMED,
                (checksum_evidence_id,),
            )
        )
    if (
        out_of_sync
        and checksum is not None
        and checksum.synchronized is True
        and checksum_evidence_id is not None
    ):
        findings.append(
            _finding(
                "ha_synchronization_observations_disagree",
                "HA synchronization observations disagree",
                (
                    "HA status reports an out-of-sync member while the compared checksum "
                    "scopes were equal at collection time."
                ),
                FindingSeverity.WARNING,
                DiagnosisStrength.CONFIRMED,
                (status_evidence_id, checksum_evidence_id),
            )
        )

    patterns = set(correlation.observed_patterns) if correlation is not None else set()
    history_ids = (history_evidence_id,) if history_evidence_id is not None else ()
    interface_ids = (interface_evidence_id,) if interface_evidence_id is not None else ()
    if HAObservedPattern.HEARTBEAT_COMMUNICATION_INSTABILITY in patterns:
        incident_count = len(correlation.episodes) if correlation is not None else 0
        findings.append(
            _finding(
                "ha_heartbeat_communication_instability",
                "HA heartbeat communication instability",
                (
                    f"{incident_count} correlated heartbeat/member incident episode(s) were "
                    "observed within the collected HA history window."
                ),
                FindingSeverity.WARNING,
                DiagnosisStrength.PROBABLE,
                history_ids,
            )
        )
    if HAObservedPattern.CLUSTER_MEMBERSHIP_INSTABILITY in patterns:
        findings.append(
            _finding(
                "ha_cluster_membership_instability",
                "HA cluster membership instability",
                "Member loss/join activity was observed in the collected HA history.",
                FindingSeverity.WARNING,
                DiagnosisStrength.PROBABLE,
                history_ids,
            )
        )
    if HAObservedPattern.REPEATED_INSTABILITY in patterns:
        episode_count = len(correlation.episodes) if correlation is not None else 0
        findings.append(
            _finding(
                "repeated_ha_member_instability",
                "Repeated HA member instability",
                f"{episode_count} separate HA incident episode(s) were observed.",
                FindingSeverity.WARNING,
                DiagnosisStrength.PROBABLE,
                history_ids,
            )
        )
    if HAObservedPattern.HEARTBEAT_INTERFACE_INSTABILITY in patterns:
        findings.append(
            _finding(
                "ha_heartbeat_link_instability",
                "HA heartbeat link/interface instability",
                "Heartbeat link transitions correlate with member/heartbeat instability.",
                FindingSeverity.WARNING,
                DiagnosisStrength.STRONG,
                tuple(dict.fromkeys(history_ids + interface_ids)),
            )
        )
    if HAObservedPattern.HEARTBEAT_INTERFACE_UNAVAILABLE in patterns:
        heartbeat_names = (
            {name.casefold() for name in correlation.heartbeat_interfaces}
            if correlation is not None
            else set()
        )
        down_count = sum(
            interface.name.casefold() in heartbeat_names
            and (
                interface.admin_state is InterfaceState.DOWN
                or interface.operational_state is InterfaceState.DOWN
            )
            for interface in interfaces
        )
        findings.append(
            _finding(
                "ha_heartbeat_interface_unavailable",
                "HA heartbeat interface unavailable",
                f"{down_count} correlated heartbeat interface(s) are currently unavailable.",
                FindingSeverity.CRITICAL,
                DiagnosisStrength.CONFIRMED,
                tuple(dict.fromkeys(history_ids + interface_ids)),
            )
        )
    if HAObservedPattern.MEMBER_RESTART in patterns:
        findings.append(
            _finding(
                "member_restart_observed",
                "HA member restart observed",
                "FortiOS HA history explicitly reports a member restart or boot event.",
                FindingSeverity.WARNING,
                DiagnosisStrength.CONFIRMED,
                history_ids,
            )
        )
    if HAObservedPattern.HA_PROCESS_RESTART in patterns:
        findings.append(
            _finding(
                "ha_process_restart_observed",
                "HA process restart observed",
                "FortiOS HA history explicitly reports an HA process restart.",
                FindingSeverity.WARNING,
                DiagnosisStrength.CONFIRMED,
                history_ids,
            )
        )
    if (
        out_of_sync
        and correlation is not None
        and HAObservedPattern.HEARTBEAT_COMMUNICATION_INSTABILITY not in patterns
        and HAObservedPattern.MEMBER_RESTART not in patterns
        and HAObservedPattern.HA_PROCESS_RESTART not in patterns
    ):
        drift_evidence_ids = tuple(
            dict.fromkeys(
                status_ids + history_ids + ((checksum_evidence_id,) if checksum_evidence_id else ())
            )
        )
        findings.append(
            _finding(
                "ha_configuration_drift_without_observed_transport_failure",
                "Configuration drift without observed HA transport failure",
                "No HA transport instability was observed in the collected history window.",
                FindingSeverity.INFO,
                DiagnosisStrength.PROBABLE,
                drift_evidence_ids,
            )
        )

    correlation_missing = correlation.missing_evidence if correlation is not None else ()
    missing = tuple(dict.fromkeys(correlation_missing + missing_evidence))
    diagnosis = _diagnosis(
        status=status,
        out_of_sync=bool(out_of_sync),
        patterns=patterns,
        findings=tuple(findings),
        missing=missing,
    )
    strength = diagnosis.strength if diagnosis is not None else DiagnosisStrength.CONFIRMED
    fault_domains = (
        correlation.fault_domains
        if correlation is not None
        else (
            (HAFaultDomain.CONFIGURATION_SYNCHRONIZATION,)
            if out_of_sync
            else (HAFaultDomain.UNKNOWN,)
        )
    )
    summary = HADiagnosticSummary(
        synchronization=synchronization,
        history_event_count=len(history.events) if history is not None else 0,
        incident_count=len(correlation.episodes) if correlation is not None else 0,
        heartbeat_instability=(HAObservedPattern.HEARTBEAT_COMMUNICATION_INSTABILITY in patterns),
        interface_instability=(
            HAObservedPattern.HEARTBEAT_INTERFACE_INSTABILITY in patterns
            or HAObservedPattern.HEARTBEAT_INTERFACE_UNAVAILABLE in patterns
        ),
        checksum_mismatch_count=checksum.mismatch_count if checksum is not None else 0,
        member_restart_observed=HAObservedPattern.MEMBER_RESTART in patterns,
        ha_process_restart_observed=HAObservedPattern.HA_PROCESS_RESTART in patterns,
        fault_domains=fault_domains,
        strength=strength,
        missing_evidence=missing,
        specific_physical_cause_confirmed=False,
    )
    return HAAssessment(findings=tuple(findings), diagnosis=diagnosis, summary=summary)


def _diagnosis(
    *,
    status: HAStatus,
    out_of_sync: bool,
    patterns: set[HAObservedPattern],
    findings: tuple[Finding, ...],
    missing: tuple[str, ...],
) -> Diagnosis | None:
    evidence_ids = tuple(
        dict.fromkeys(evidence_id for finding in findings for evidence_id in finding.evidence_ids)
    )
    if HAObservedPattern.HA_PROCESS_RESTART in patterns:
        return Diagnosis(
            summary="An HA process restart was directly observed in FortiOS history.",
            strength=DiagnosisStrength.CONFIRMED,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if HAObservedPattern.MEMBER_RESTART in patterns:
        return Diagnosis(
            summary="An HA member restart or boot was directly observed in FortiOS history.",
            strength=DiagnosisStrength.CONFIRMED,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if HAObservedPattern.HEARTBEAT_INTERFACE_INSTABILITY in patterns:
        return Diagnosis(
            summary=(
                "Multiple typed observations narrow the fault domain to HA heartbeat "
                "link/interface instability."
            ),
            strength=DiagnosisStrength.STRONG,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if HAObservedPattern.HEARTBEAT_INTERFACE_UNAVAILABLE in patterns:
        return Diagnosis(
            summary=(
                "A correlated HA heartbeat interface is unavailable; the physical cause "
                "is not identified by device evidence."
            ),
            strength=DiagnosisStrength.STRONG,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if HAObservedPattern.HEARTBEAT_COMMUNICATION_INSTABILITY in patterns:
        prefix = "HA configuration is out of sync, and " if out_of_sync else ""
        return Diagnosis(
            summary=(
                f"{prefix}repeated HA heartbeat/member events narrow the likely fault "
                "domain to HA heartbeat communication."
            ),
            strength=DiagnosisStrength.PROBABLE,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if out_of_sync:
        return Diagnosis(
            summary="FortiOS directly reports HA configuration out of sync.",
            strength=DiagnosisStrength.CONFIRMED,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if status.health in {HealthStatus.DEGRADED, HealthStatus.UNHEALTHY}:
        return Diagnosis(
            summary="FortiOS directly reports degraded HA health.",
            strength=DiagnosisStrength.CONFIRMED,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    if HAObservedPattern.CLUSTER_MEMBERSHIP_INSTABILITY in patterns:
        return Diagnosis(
            summary=(
                "HA cluster membership instability was observed, but its specific cause "
                "is not identified."
            ),
            strength=DiagnosisStrength.PROBABLE,
            evidence_ids=evidence_ids,
            missing_evidence=missing,
        )
    return None


def _synchronization(status: HAStatus) -> HASynchronizationState:
    states = {member.synchronization for member in status.members}
    if HASynchronizationState.OUT_OF_SYNC in states:
        return HASynchronizationState.OUT_OF_SYNC
    if states and states == {HASynchronizationState.IN_SYNC}:
        return HASynchronizationState.IN_SYNC
    return HASynchronizationState.UNKNOWN


def _finding(
    code: str,
    title: str,
    summary: str,
    severity: FindingSeverity,
    strength: DiagnosisStrength,
    evidence_ids: tuple[UUID, ...],
) -> Finding:
    return Finding(
        code=code,
        title=title,
        summary=summary,
        severity=severity,
        strength=strength,
        evidence_ids=evidence_ids,
    )


__all__ = ["HAAssessment", "build_ha_assessment"]
