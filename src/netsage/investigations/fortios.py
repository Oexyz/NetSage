"""Deterministic FortiOS investigations built exclusively on Broker evidence."""

from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from ipaddress import IPv4Network
from uuid import UUID, uuid4

from netsage.evidence import (
    BGPStatusEvidencePayload,
    EvidenceCollectionFailure,
    EvidenceCollector,
    EvidenceEnvelope,
    HAStatusEvidencePayload,
    InterfacesEvidencePayload,
    IPsecStatusEvidencePayload,
    OSPFStatusEvidencePayload,
    RoutesEvidencePayload,
    SDWANStatusEvidencePayload,
    SystemHealthEvidencePayload,
)
from netsage.investigations.models import (
    Diagnosis,
    DiagnosisStrength,
    Finding,
    FindingSeverity,
    FortiOSInvestigationFocus,
    Investigation,
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.models import (
    HEALTH_DEGRADED_THRESHOLD_PERCENT,
    HEALTH_UNHEALTHY_THRESHOLD_PERCENT,
    BGPSessionState,
    Capability,
    HASynchronizationState,
    HealthStatus,
    InterfaceState,
    IPsecPhaseState,
    IPsecStatus,
    OSPFNeighborState,
    SDWANPathState,
    SDWANSLAState,
)
from netsage.security import SecretRedactor

_DEFAULT_IPV4_ROUTE = IPv4Network("0.0.0.0/0")
_MISSING_LABELS = {
    "get_device_facts": "device facts",
    "get_interfaces": "interface state",
    "get_routes": "route table",
    "get_system_health": "system health",
    "get_ha_status": "HA status",
    "get_sdwan_status": "SD-WAN status",
    "get_ipsec_status": "IPsec status",
    "get_bgp_status": "BGP status",
    "get_ospf_status": "OSPF status",
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

    async def investigate(
        self, device_id: str, focus: FortiOSInvestigationFocus
    ) -> InvestigationReport:
        """Dispatch one explicit feature-aware workflow without collecting every domain."""

        if focus is FortiOSInvestigationFocus.HEALTH:
            return await self.investigate_health(device_id)
        if focus is FortiOSInvestigationFocus.HA:
            return await self.investigate_ha(device_id)
        if focus is FortiOSInvestigationFocus.SDWAN:
            return await self.investigate_sdwan(device_id)
        if focus is FortiOSInvestigationFocus.IPSEC:
            return await self.investigate_ipsec(device_id)
        return await self.investigate_dynamic_routing(device_id)

    async def investigate_ha(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.HA_HEALTH)
        observation = await self._collector.collect(
            investigation_id=investigation.investigation_id,
            device_id=device_id,
            operation="get_ha_status",
            capability=Capability.HA,
        )
        evidence, failures = self._partition((observation,))
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: list[Finding] = []
        status_observation = self._find_payload(evidence, HAStatusEvidencePayload)
        if status_observation is not None:
            item, payload = status_observation
            status = payload.status
            if status.truncated:
                diagnosis = self._insufficient(
                    evidence,
                    "HA member collection was truncated",
                )
            elif status.enabled is False:
                findings.append(
                    self._finding(
                        "ha_disabled",
                        "HA disabled",
                        "FortiOS reports that HA is not enabled.",
                        FindingSeverity.INFO,
                        item,
                    )
                )
            else:
                out_of_sync = tuple(
                    member
                    for member in status.members
                    if member.synchronization is HASynchronizationState.OUT_OF_SYNC
                )
                if out_of_sync:
                    findings.append(
                        self._finding(
                            "ha_configuration_out_of_sync",
                            "HA configuration out of sync",
                            f"FortiOS reports {len(out_of_sync)} HA member(s) out of sync.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                    diagnosis = Diagnosis(
                        summary="FortiOS directly reports HA configuration out of sync.",
                        strength=DiagnosisStrength.CONFIRMED,
                        evidence_ids=(item.evidence_id,),
                    )
                elif status.health in {HealthStatus.DEGRADED, HealthStatus.UNHEALTHY}:
                    severity = (
                        FindingSeverity.CRITICAL
                        if status.health is HealthStatus.UNHEALTHY
                        else FindingSeverity.WARNING
                    )
                    findings.append(
                        self._finding(
                            "ha_health_degraded",
                            "HA health degraded",
                            f"FortiOS reports HA health as {status.health.value}.",
                            severity,
                            item,
                        )
                    )
                    diagnosis = Diagnosis(
                        summary="FortiOS directly reports degraded HA health.",
                        strength=DiagnosisStrength.CONFIRMED,
                        evidence_ids=(item.evidence_id,),
                    )
                elif status.enabled and status.members:
                    findings.append(
                        self._finding(
                            "ha_cluster_healthy",
                            "HA cluster healthy",
                            "Observed HA members are synchronized and HA health is not degraded.",
                            FindingSeverity.INFO,
                            item,
                        )
                    )
                if status.enabled and len(status.members) < 2:
                    findings.append(
                        self._finding(
                            "ha_member_count_low",
                            "Fewer than two HA members observed",
                            "Only one HA member was observed; expected membership is not known.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
        return self._report(investigation, evidence, failures, findings, diagnosis)

    async def investigate_sdwan(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.SDWAN_HEALTH)
        observation = await self._collector.collect(
            investigation_id=investigation.investigation_id,
            device_id=device_id,
            operation="get_sdwan_status",
            capability=Capability.SDWAN,
        )
        evidence, failures = self._partition((observation,))
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: list[Finding] = []
        status_observation = self._find_payload(evidence, SDWANStatusEvidencePayload)
        if status_observation is not None:
            item, payload = status_observation
            status = payload.status
            if status.truncated:
                diagnosis = self._insufficient(evidence, "SD-WAN collection was truncated")
            elif status.enabled is False:
                findings.append(
                    self._finding(
                        "sdwan_disabled",
                        "SD-WAN disabled",
                        "FortiOS reports that SD-WAN is not enabled.",
                        FindingSeverity.INFO,
                        item,
                    )
                )
            elif status.enabled and not status.health_checks:
                diagnosis = self._insufficient(
                    evidence,
                    "SD-WAN health-check state was unavailable",
                )
            else:
                dead = tuple(
                    check for check in status.health_checks if check.state is SDWANPathState.DEAD
                )
                alive = tuple(
                    check for check in status.health_checks if check.state is SDWANPathState.ALIVE
                )
                failing_sla = tuple(
                    check
                    for check in status.health_checks
                    if check.sla_state is SDWANSLAState.FAILING
                )
                if dead:
                    findings.append(
                        self._finding(
                            "sdwan_member_down",
                            "SD-WAN path down",
                            f"FortiOS reports {len(dead)} SD-WAN health-check path(s) dead.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                if failing_sla:
                    findings.append(
                        self._finding(
                            "sdwan_sla_failing",
                            "SD-WAN SLA failing",
                            f"FortiOS reports {len(failing_sla)} path(s) failing SLA.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                if dead and alive:
                    findings.append(
                        self._finding(
                            "sdwan_healthy_alternative",
                            "Healthy SD-WAN alternative available",
                            "At least one dead and one alive SD-WAN path were observed.",
                            FindingSeverity.INFO,
                            item,
                        )
                    )
                if status.health_checks and not alive:
                    diagnosis = Diagnosis(
                        summary="FortiOS reports no alive SD-WAN health-check path.",
                        strength=DiagnosisStrength.CONFIRMED,
                        evidence_ids=(item.evidence_id,),
                    )
                elif not dead and not failing_sla and status.health_checks:
                    findings.append(
                        self._finding(
                            "sdwan_paths_healthy",
                            "SD-WAN paths healthy",
                            "FortiOS reports the observed SD-WAN paths alive with "
                            "no explicit SLA failure.",
                            FindingSeverity.INFO,
                            item,
                        )
                    )
        return self._report(investigation, evidence, failures, findings, diagnosis)

    async def investigate_ipsec(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.IPSEC_HEALTH)
        observations = await self._collect(
            investigation,
            (
                ("get_ipsec_status", Capability.IPSEC),
                ("get_interfaces", Capability.INTERFACES),
            ),
        )
        evidence, failures = self._partition(observations)
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: list[Finding] = []
        ipsec_observation = self._find_payload(evidence, IPsecStatusEvidencePayload)
        interface_observation = self._find_payload(evidence, InterfacesEvidencePayload)
        if ipsec_observation is not None:
            ipsec_evidence, payload = ipsec_observation
            status = payload.status
            if status.truncated:
                diagnosis = self._insufficient(evidence, "IPsec collection was truncated")
            elif status.enabled is False:
                findings.append(
                    self._finding(
                        "ipsec_disabled",
                        "IPsec disabled",
                        "FortiOS reports that IPsec is not enabled.",
                        FindingSeverity.INFO,
                        ipsec_evidence,
                    )
                )
            elif status.enabled is None and not status.phase1 and not status.tunnels:
                diagnosis = self._insufficient(
                    evidence,
                    "active IKE or IPsec security-association state was unavailable",
                )
            else:
                down_phase1 = tuple(
                    phase for phase in status.phase1 if phase.state is IPsecPhaseState.DOWN
                )
                missing_phase2 = tuple(
                    tunnel
                    for tunnel in status.tunnels
                    if tunnel.phase1_state is IPsecPhaseState.ESTABLISHED
                    and not any(
                        phase.state in {IPsecPhaseState.ESTABLISHED, IPsecPhaseState.REKEYING}
                        for phase in tunnel.phase2
                    )
                )
                if down_phase1:
                    findings.append(
                        self._finding(
                            "ipsec_phase1_down",
                            "IPsec Phase 1 down",
                            f"FortiOS reports {len(down_phase1)} Phase 1 association(s) down.",
                            FindingSeverity.WARNING,
                            ipsec_evidence,
                        )
                    )
                    diagnosis = Diagnosis(
                        summary=(
                            "FortiOS directly reports IPsec Phase 1 down; the cause "
                            "is not established."
                        ),
                        strength=DiagnosisStrength.CONFIRMED,
                        evidence_ids=(ipsec_evidence.evidence_id,),
                    )
                if missing_phase2:
                    findings.append(
                        self._finding(
                            "ipsec_phase2_missing",
                            "IPsec Phase 2 unavailable",
                            f"Observed {len(missing_phase2)} established Phase 1 "
                            "tunnel(s) without an active Phase 2 SA.",
                            FindingSeverity.WARNING,
                            ipsec_evidence,
                        )
                    )
                    diagnosis = Diagnosis(
                        summary="Phase 1 is established but no active Phase 2 SA was observed.",
                        strength=DiagnosisStrength.CONFIRMED,
                        evidence_ids=(ipsec_evidence.evidence_id,),
                    )
                correlation = self._ipsec_interface_correlation(
                    status,
                    interface_observation,
                )
                if correlation is not None:
                    interface_evidence, count = correlation
                    findings.append(
                        Finding(
                            code="ipsec_bound_interface_down",
                            title="IPsec tunnel and bound interface down",
                            summary=(
                                f"Observed {count} down IPsec tunnel(s) bound to a down interface."
                            ),
                            severity=FindingSeverity.CRITICAL,
                            evidence_ids=(
                                ipsec_evidence.evidence_id,
                                interface_evidence.evidence_id,
                            ),
                        )
                    )
                    diagnosis = Diagnosis(
                        summary=(
                            "IPsec is down while its bound interface is also down; "
                            "evidence places the fault domain at or before that interface."
                        ),
                        strength=DiagnosisStrength.STRONG,
                        evidence_ids=(
                            ipsec_evidence.evidence_id,
                            interface_evidence.evidence_id,
                        ),
                    )
                if status.tunnels and not down_phase1 and not missing_phase2:
                    findings.append(
                        self._finding(
                            "ipsec_tunnels_established",
                            "IPsec tunnels established",
                            "No down Phase 1 or missing active Phase 2 association was observed.",
                            FindingSeverity.INFO,
                            ipsec_evidence,
                        )
                    )
        if failures:
            diagnosis = self._partial_diagnosis(evidence, failures)
        return self._report(investigation, evidence, failures, findings, diagnosis)

    async def investigate_dynamic_routing(self, device_id: str) -> InvestigationReport:
        investigation = self._start(device_id, InvestigationKind.DYNAMIC_ROUTING_HEALTH)
        observations = await self._collect(
            investigation,
            (
                ("get_bgp_status", Capability.BGP),
                ("get_ospf_status", Capability.OSPF),
            ),
        )
        evidence, failures = self._partition(observations)
        diagnosis = self._partial_diagnosis(evidence, failures)
        findings: list[Finding] = []
        affected_evidence: list[UUID] = []
        bgp_observation = self._find_payload(evidence, BGPStatusEvidencePayload)
        if bgp_observation is not None:
            item, bgp_payload = bgp_observation
            bgp_status = bgp_payload.status
            if bgp_status.truncated:
                diagnosis = self._insufficient(evidence, "BGP neighbor collection was truncated")
            elif bgp_status.enabled is False:
                findings.append(
                    self._finding(
                        "bgp_disabled",
                        "BGP disabled",
                        "FortiOS reports that BGP is not enabled.",
                        FindingSeverity.INFO,
                        item,
                    )
                )
            else:
                down = tuple(
                    neighbor
                    for neighbor in bgp_status.neighbors
                    if neighbor.state is not BGPSessionState.ESTABLISHED
                )
                zero_prefixes = tuple(
                    neighbor
                    for neighbor in bgp_status.neighbors
                    if neighbor.state is BGPSessionState.ESTABLISHED
                    and neighbor.prefixes_received == 0
                )
                if down:
                    findings.append(
                        self._finding(
                            "bgp_neighbor_not_established",
                            "BGP neighbor not established",
                            f"FortiOS reports {len(down)} BGP neighbor(s) not established.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                    affected_evidence.append(item.evidence_id)
                if zero_prefixes:
                    findings.append(
                        self._finding(
                            "bgp_zero_received_prefixes",
                            "BGP neighbor has no received prefixes",
                            f"Observed {len(zero_prefixes)} established BGP neighbor(s) "
                            "with zero received prefixes.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                if bgp_status.enabled and not bgp_status.neighbors:
                    findings.append(
                        self._finding(
                            "bgp_no_neighbors",
                            "No BGP neighbors observed",
                            "BGP is present but no neighbor rows were observed.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
        ospf_observation = self._find_payload(evidence, OSPFStatusEvidencePayload)
        if ospf_observation is not None:
            item, ospf_payload = ospf_observation
            ospf_status = ospf_payload.status
            if ospf_status.truncated:
                diagnosis = self._insufficient(evidence, "OSPF neighbor collection was truncated")
            elif ospf_status.enabled is False:
                findings.append(
                    self._finding(
                        "ospf_disabled",
                        "OSPF disabled",
                        "FortiOS reports that OSPF is not enabled.",
                        FindingSeverity.INFO,
                        item,
                    )
                )
            else:
                not_full = tuple(
                    neighbor
                    for neighbor in ospf_status.neighbors
                    if neighbor.state is not OSPFNeighborState.FULL
                )
                if not_full:
                    findings.append(
                        self._finding(
                            "ospf_neighbor_not_full",
                            "OSPF neighbor not FULL",
                            f"FortiOS reports {len(not_full)} OSPF neighbor(s) not FULL.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
                    affected_evidence.append(item.evidence_id)
                if ospf_status.enabled and not ospf_status.neighbors:
                    findings.append(
                        self._finding(
                            "ospf_no_neighbors",
                            "No OSPF neighbors observed",
                            "OSPF is present but no neighbor rows were observed.",
                            FindingSeverity.WARNING,
                            item,
                        )
                    )
        if affected_evidence and diagnosis is None:
            diagnosis = Diagnosis(
                summary=(
                    "Dynamic-routing neighbor state is degraded; the underlying cause "
                    "is not established."
                ),
                strength=DiagnosisStrength.CONFIRMED,
                evidence_ids=tuple(dict.fromkeys(affected_evidence)),
            )
        if failures:
            diagnosis = self._partial_diagnosis(evidence, failures)
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

    @staticmethod
    def _finding(
        code: str,
        title: str,
        summary: str,
        severity: FindingSeverity,
        evidence: EvidenceEnvelope,
    ) -> Finding:
        return Finding(
            code=code,
            title=title,
            summary=summary,
            severity=severity,
            evidence_ids=(evidence.evidence_id,),
        )

    @staticmethod
    def _insufficient(evidence: Sequence[EvidenceEnvelope], missing: str) -> Diagnosis:
        return Diagnosis(
            summary="A reliable conclusion is not possible with incomplete semantic evidence.",
            strength=DiagnosisStrength.INSUFFICIENT,
            evidence_ids=tuple(item.evidence_id for item in evidence),
            missing_evidence=(missing,),
        )

    @staticmethod
    def _ipsec_interface_correlation(
        status: IPsecStatus,
        interface_observation: tuple[EvidenceEnvelope, InterfacesEvidencePayload] | None,
    ) -> tuple[EvidenceEnvelope, int] | None:
        if interface_observation is None:
            return None
        interface_evidence, interface_payload = interface_observation
        down_interfaces = {
            interface.name
            for interface in interface_payload.interfaces
            if interface.admin_state is InterfaceState.DOWN
            or interface.operational_state is InterfaceState.DOWN
        }
        affected = tuple(
            tunnel
            for tunnel in status.tunnels
            if tunnel.phase1_state is IPsecPhaseState.DOWN
            and tunnel.interface is not None
            and tunnel.interface in down_interfaces
        )
        return (interface_evidence, len(affected)) if affected else None

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
