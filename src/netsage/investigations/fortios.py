"""Deterministic FortiOS investigations built exclusively on Broker evidence."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Network
from uuid import UUID, uuid4

from netsage.evidence import (
    EvidenceCollectionFailure,
    EvidenceCollector,
    EvidenceEnvelope,
    InterfacesEvidencePayload,
    RoutesEvidencePayload,
    SystemHealthEvidencePayload,
)
from netsage.investigations.models import (
    Diagnosis,
    DiagnosisStrength,
    Finding,
    FindingSeverity,
    Investigation,
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.models import (
    HEALTH_DEGRADED_THRESHOLD_PERCENT,
    HEALTH_UNHEALTHY_THRESHOLD_PERCENT,
    Capability,
    HealthStatus,
    InterfaceState,
)
from netsage.security import SecretRedactor

_DEFAULT_IPV4_ROUTE = IPv4Network("0.0.0.0/0")
_MISSING_LABELS = {
    "get_device_facts": "device facts",
    "get_interfaces": "interface state",
    "get_routes": "route table",
    "get_system_health": "system health",
}


class FortiOSInvestigator:
    """Run fixed FortiOS workflows without AI, raw commands, or direct driver access."""

    def __init__(
        self,
        *,
        collector: EvidenceCollector,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        investigation_id_factory: Callable[[], UUID] = uuid4,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._collector = collector
        self._clock = clock
        self._investigation_id_factory = investigation_id_factory
        self._redactor = redactor or SecretRedactor()

    async def investigate_health(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.FORTIGATE_HEALTH)
        observations = await self._collect(
            investigation,
            (
                ("get_device_facts", Capability.FACTS),
                ("get_interfaces", Capability.INTERFACES),
                ("get_system_health", Capability.SYSTEM_HEALTH),
                ("get_routes", Capability.ROUTES),
            ),
        )
        evidence, failures = self._partition(observations)
        findings = self._health_findings(evidence)
        diagnosis = self._partial_diagnosis(evidence, failures)
        if diagnosis is None:
            route_observation = self._find_payload(evidence, RoutesEvidencePayload)
            if route_observation and not self._has_active_default_route(route_observation[1]):
                route_evidence, _route_payload = route_observation
                diagnosis = Diagnosis(
                    summary="No active IPv4 default route exists.",
                    strength=DiagnosisStrength.CONFIRMED,
                    evidence_ids=(route_evidence.evidence_id,),
                )
        return self._report(investigation, evidence, failures, findings, diagnosis)

    async def investigate_default_route(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.DEFAULT_ROUTE)
        observation = await self._collector.collect(
            investigation_id=investigation.investigation_id,
            device_id=device_id,
            operation="get_routes",
            capability=Capability.ROUTES,
        )
        evidence, failures = self._partition((observation,))
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: tuple[Finding, ...] = ()
        route_observation = self._find_payload(evidence, RoutesEvidencePayload)
        if route_observation is not None:
            route_evidence, route_payload = route_observation
            if self._has_active_default_route(route_payload):
                findings = (
                    Finding(
                        code="active_default_route",
                        title="Active IPv4 default route",
                        summary="An active IPv4 default route is present.",
                        severity=FindingSeverity.INFO,
                        evidence_ids=(route_evidence.evidence_id,),
                    ),
                )
            else:
                findings = (
                    Finding(
                        code="missing_default_route",
                        title="Missing IPv4 default route",
                        summary="No active IPv4 default route was observed.",
                        severity=FindingSeverity.WARNING,
                        evidence_ids=(route_evidence.evidence_id,),
                    ),
                )
                diagnosis = Diagnosis(
                    summary="No active IPv4 default route exists.",
                    strength=DiagnosisStrength.CONFIRMED,
                    evidence_ids=(route_evidence.evidence_id,),
                )
        return self._report(investigation, evidence, failures, findings, diagnosis)

    async def investigate_interface_state(
        self, device_id: str, interface_name: str
    ) -> InvestigationReport:
        safe_interface = self._redactor.redact_text(interface_name).strip()
        if not safe_interface:
            raise ValueError("interface name must not be blank")
        investigation = self._start(
            device_id,
            InvestigationKind.INTERFACE_STATE,
            target_interface=safe_interface,
        )
        observation = await self._collector.collect(
            investigation_id=investigation.investigation_id,
            device_id=device_id,
            operation="get_interfaces",
            capability=Capability.INTERFACES,
        )
        evidence, failures = self._partition((observation,))
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: tuple[Finding, ...] = ()
        interface_observation = self._find_payload(evidence, InterfacesEvidencePayload)
        if interface_observation is not None:
            interface_evidence, interface_payload = interface_observation
            interface = next(
                (item for item in interface_payload.interfaces if item.name == safe_interface),
                None,
            )
            if interface is None:
                diagnosis = Diagnosis(
                    summary="The requested interface state cannot be determined.",
                    strength=DiagnosisStrength.INSUFFICIENT,
                    evidence_ids=(interface_evidence.evidence_id,),
                    missing_evidence=(
                        f"interface {safe_interface} was not present in the collected "
                        "interface data",
                    ),
                )
            elif interface.admin_state is InterfaceState.DOWN:
                findings = (
                    Finding(
                        code="interface_administratively_down",
                        title="Interface administratively down",
                        summary=f"Interface {safe_interface} is administratively disabled.",
                        severity=FindingSeverity.INFO,
                        evidence_ids=(interface_evidence.evidence_id,),
                    ),
                )
                diagnosis = Diagnosis(
                    summary=f"Interface {safe_interface} is administratively disabled.",
                    strength=DiagnosisStrength.CONFIRMED,
                    evidence_ids=(interface_evidence.evidence_id,),
                )
            elif (
                interface.admin_state is InterfaceState.UP
                and interface.operational_state is InterfaceState.DOWN
            ):
                findings = (
                    Finding(
                        code="interface_operationally_down",
                        title="Interface operationally down",
                        summary=(
                            f"Interface {safe_interface} is operationally down while "
                            "administratively enabled."
                        ),
                        severity=FindingSeverity.WARNING,
                        evidence_ids=(interface_evidence.evidence_id,),
                    ),
                )
                diagnosis = Diagnosis(
                    summary=(
                        f"Interface {safe_interface} is operationally down while "
                        "administratively enabled; the physical or logical cause is not known."
                    ),
                    strength=DiagnosisStrength.CONFIRMED,
                    evidence_ids=(interface_evidence.evidence_id,),
                )
            elif (
                interface.admin_state is InterfaceState.UP
                and interface.operational_state is InterfaceState.UP
            ):
                findings = (
                    Finding(
                        code="interface_up",
                        title="Interface operational",
                        summary=(
                            f"Interface {safe_interface} is administratively and operationally up."
                        ),
                        severity=FindingSeverity.INFO,
                        evidence_ids=(interface_evidence.evidence_id,),
                    ),
                )
            else:
                diagnosis = Diagnosis(
                    summary="The requested interface state is not sufficiently known.",
                    strength=DiagnosisStrength.INSUFFICIENT,
                    evidence_ids=(interface_evidence.evidence_id,),
                    missing_evidence=(f"complete state for interface {safe_interface}",),
                )
        return self._report(investigation, evidence, failures, findings, diagnosis)

    def _start(
        self,
        device_id: str,
        kind: InvestigationKind,
        *,
        target_interface: str | None = None,
    ) -> Investigation:
        return Investigation(
            investigation_id=self._investigation_id_factory(),
            device_id=device_id,
            kind=kind,
            started_at=self._clock(),
            target_interface=target_interface,
        )

    async def _collect(
        self,
        investigation: Investigation,
        operations: Sequence[tuple[str, Capability]],
    ) -> tuple[EvidenceEnvelope | EvidenceCollectionFailure, ...]:
        observations = []
        for operation, capability in operations:
            observations.append(
                await self._collector.collect(
                    investigation_id=investigation.investigation_id,
                    device_id=investigation.device_id,
                    operation=operation,
                    capability=capability,
                )
            )
        return tuple(observations)

    @staticmethod
    def _partition(
        observations: Sequence[EvidenceEnvelope | EvidenceCollectionFailure],
    ) -> tuple[tuple[EvidenceEnvelope, ...], tuple[EvidenceCollectionFailure, ...]]:
        evidence = tuple(item for item in observations if isinstance(item, EvidenceEnvelope))
        failures = tuple(
            item for item in observations if isinstance(item, EvidenceCollectionFailure)
        )
        return evidence, failures

    @staticmethod
    def _find_payload[PayloadT](
        evidence: Sequence[EvidenceEnvelope], payload_type: type[PayloadT]
    ) -> tuple[EvidenceEnvelope, PayloadT] | None:
        for item in evidence:
            if isinstance(item.payload, payload_type):
                return item, item.payload
        return None

    @staticmethod
    def _has_active_default_route(payload: RoutesEvidencePayload) -> bool:
        return any(
            route.prefix == _DEFAULT_IPV4_ROUTE and route.selected for route in payload.routes
        )

    def _health_findings(self, evidence: Sequence[EvidenceEnvelope]) -> tuple[Finding, ...]:
        findings: list[Finding] = []
        health_observation = self._find_payload(evidence, SystemHealthEvidencePayload)
        if health_observation is not None:
            health_evidence, health_payload = health_observation
            health = health_payload.health
            findings.extend(self._resource_findings(health_evidence, "CPU", health.cpu_percent))
            findings.extend(
                self._resource_findings(health_evidence, "memory", health.memory_percent)
            )
            if (
                health.status is not HealthStatus.HEALTHY
                and health.cpu_percent is None
                and health.memory_percent is None
            ):
                findings.append(
                    Finding(
                        code="system_health_degraded",
                        title="System health not healthy",
                        summary=f"Normalized system health is {health.status.value}.",
                        severity=FindingSeverity.WARNING,
                        evidence_ids=(health_evidence.evidence_id,),
                    )
                )
        interface_observation = self._find_payload(evidence, InterfacesEvidencePayload)
        if interface_observation is not None:
            interface_evidence, interface_payload = interface_observation
            for interface in interface_payload.interfaces:
                if interface.admin_state is InterfaceState.DOWN:
                    findings.append(
                        Finding(
                            code="interface_administratively_down",
                            title="Interface administratively down",
                            summary=f"Interface {interface.name} is administratively disabled.",
                            severity=FindingSeverity.INFO,
                            evidence_ids=(interface_evidence.evidence_id,),
                        )
                    )
                elif interface.operational_state is InterfaceState.DOWN:
                    findings.append(
                        Finding(
                            code="interface_operationally_down",
                            title="Interface operationally down",
                            summary=(
                                f"Interface {interface.name} is operationally down while "
                                "administratively enabled."
                            ),
                            severity=FindingSeverity.WARNING,
                            evidence_ids=(interface_evidence.evidence_id,),
                        )
                    )
        route_observation = self._find_payload(evidence, RoutesEvidencePayload)
        if route_observation is not None:
            route_evidence, route_payload = route_observation
            has_default = self._has_active_default_route(route_payload)
            findings.append(
                Finding(
                    code="active_default_route" if has_default else "missing_default_route",
                    title="Active IPv4 default route"
                    if has_default
                    else "Missing IPv4 default route",
                    summary=(
                        "An active IPv4 default route is present."
                        if has_default
                        else "No active IPv4 default route was observed."
                    ),
                    severity=FindingSeverity.INFO if has_default else FindingSeverity.WARNING,
                    evidence_ids=(route_evidence.evidence_id,),
                )
            )
        return tuple(findings)

    @staticmethod
    def _resource_findings(
        evidence: EvidenceEnvelope, resource: str, percent: float | None
    ) -> tuple[Finding, ...]:
        if percent is None or percent < HEALTH_DEGRADED_THRESHOLD_PERCENT:
            return ()
        critical = percent >= HEALTH_UNHEALTHY_THRESHOLD_PERCENT
        normalized_resource = resource.casefold()
        return (
            Finding(
                code=f"high_{normalized_resource}",
                title=f"High {resource} usage",
                summary=f"Observed {resource} usage is {percent:g}%.",
                severity=FindingSeverity.CRITICAL if critical else FindingSeverity.WARNING,
                evidence_ids=(evidence.evidence_id,),
            ),
        )

    @staticmethod
    def _partial_diagnosis(
        evidence: Sequence[EvidenceEnvelope],
        failures: Sequence[EvidenceCollectionFailure],
    ) -> Diagnosis | None:
        if not failures:
            return None
        missing = tuple(
            f"{_MISSING_LABELS.get(failure.operation, failure.operation)} could not be collected"
            for failure in failures
        )
        return Diagnosis(
            summary="A reliable root-cause diagnosis is not possible with partial evidence.",
            strength=DiagnosisStrength.INSUFFICIENT,
            evidence_ids=tuple(item.evidence_id for item in evidence),
            missing_evidence=missing,
        )

    def _report(
        self,
        investigation: Investigation,
        evidence: Sequence[EvidenceEnvelope],
        failures: Sequence[EvidenceCollectionFailure],
        findings: Sequence[Finding],
        diagnosis: Diagnosis | None,
    ) -> InvestigationReport:
        if failures or (
            diagnosis is not None and diagnosis.strength is DiagnosisStrength.INSUFFICIENT
        ):
            status = InvestigationStatus.INSUFFICIENT
        elif any(finding.severity is FindingSeverity.CRITICAL for finding in findings):
            status = InvestigationStatus.CRITICAL
        elif any(finding.severity is FindingSeverity.WARNING for finding in findings):
            status = InvestigationStatus.WARNING
        else:
            status = InvestigationStatus.HEALTHY
        return InvestigationReport(
            investigation=investigation,
            completed_at=self._clock(),
            status=status,
            evidence_ids=tuple(item.evidence_id for item in evidence),
            failures=tuple(failures),
            findings=tuple(findings),
            diagnosis=diagnosis,
        )
