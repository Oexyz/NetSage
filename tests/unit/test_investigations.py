from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from pathlib import Path
from uuid import UUID

import pytest

from netsage.broker import AuditResult, InMemoryAuditSink, ToolBroker
from netsage.drivers import FakeDriver
from netsage.drivers.fortios.semantic import (
    parse_ha_checksum_nonsync,
    parse_ha_history,
)
from netsage.evidence import (
    EvidenceCollectionFailure,
    EvidenceCollector,
    EvidenceFactory,
    InMemoryEvidenceStore,
    RoutesEvidencePayload,
)
from netsage.inventory import Inventory
from netsage.investigations import (
    DiagnosisStrength,
    FindingSeverity,
    FortiOSInvestigator,
    InvestigationReport,
    InvestigationStatus,
    render_investigation_report,
)
from netsage.models import (
    BGPNeighbor,
    BGPSessionState,
    BGPStatus,
    Capability,
    DeviceFacts,
    DeviceRef,
    HAMember,
    HAStatus,
    HASynchronizationState,
    HealthStatus,
    Interface,
    InterfaceState,
    IPsecPhase1,
    IPsecPhase2,
    IPsecPhaseState,
    IPsecStatus,
    IPsecTunnel,
    OSPFNeighbor,
    OSPFNeighborState,
    OSPFStatus,
    PingResult,
    Route,
    SDWANHealthCheck,
    SDWANMember,
    SDWANPathState,
    SDWANSLAState,
    SDWANStatus,
    SystemHealth,
)
from netsage.policies import ObservePolicy
from netsage.tools import REVIEWED_HA_DIAGNOSTIC_TOOLS, StructuredDriverToolSet

NOW = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
DEVICE_ID = "fortigate-lab"
FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"


@dataclass(frozen=True)
class Runtime:
    investigator: FortiOSInvestigator
    collector: EvidenceCollector
    store: InMemoryEvidenceStore
    audit: InMemoryAuditSink


def facts() -> DeviceFacts:
    return DeviceFacts(
        device_id=DEVICE_ID,
        vendor="Fortinet",
        model="FortiGate-Synthetic",
        os_version="7.4.5",
    )


def interface(
    *,
    name: str = "port1",
    admin: InterfaceState = InterfaceState.UP,
    operational: InterfaceState = InterfaceState.UP,
    description: str | None = None,
) -> Interface:
    return Interface(
        device_id=DEVICE_ID,
        name=name,
        admin_state=admin,
        operational_state=operational,
        description=description,
    )


def default_route() -> Route:
    return Route(
        device_id=DEVICE_ID,
        prefix=ip_network("0.0.0.0/0"),
        protocol="static",
        next_hop=ip_address("192.0.2.254"),
        selected=True,
    )


def healthy_driver(
    *,
    interfaces: tuple[Interface, ...] = (),
    routes: tuple[Route, ...] = (default_route(),),
    health: SystemHealth | None = None,
) -> FakeDriver:
    return FakeDriver(
        facts=facts(),
        interfaces=interfaces,
        routes=routes,
        system_health=health
        or SystemHealth(
            device_id=DEVICE_ID,
            status=HealthStatus.HEALTHY,
            cpu_percent=10,
            memory_percent=40,
        ),
    )


def make_runtime(
    driver: FakeDriver,
    *,
    capabilities: frozenset[Capability] | None = None,
) -> Runtime:
    device = DeviceRef(
        name=DEVICE_ID,
        host="192.0.2.1",
        platform="fortios",
        credential_ref="synthetic-readonly",
        capabilities=capabilities if capabilities is not None else driver.capabilities,
    )
    inventory = Inventory(devices={device.name: device})
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=inventory,
        policy=ObservePolicy(allowed_diagnostics=REVIEWED_HA_DIAGNOSTIC_TOOLS),
        audit_sink=audit,
        user="test-operator",
    )
    StructuredDriverToolSet({device.name: driver}).register(broker)
    evidence_ids = iter(UUID(int=value) for value in range(1, 32))
    store = InMemoryEvidenceStore()
    collector = EvidenceCollector(
        broker=broker,
        inventory=inventory,
        factory=EvidenceFactory(
            clock=lambda: NOW,
            evidence_id_factory=lambda: next(evidence_ids),
        ),
        store=store,
        driver="FakeDriver",
        clock=lambda: NOW,
    )
    investigator = FortiOSInvestigator(
        collector=collector,
        clock=lambda: NOW,
        investigation_id_factory=lambda: UUID(int=100),
    )
    return Runtime(investigator=investigator, collector=collector, store=store, audit=audit)


@pytest.mark.asyncio
async def test_healthy_fortigate_pipeline_is_deterministic_and_broker_audited() -> None:
    runtime = make_runtime(healthy_driver(interfaces=(interface(),)))

    first = await runtime.investigator.investigate_health(DEVICE_ID)
    second_runtime = make_runtime(healthy_driver(interfaces=(interface(),)))
    second = await second_runtime.investigator.investigate_health(DEVICE_ID)

    assert first.status is InvestigationStatus.HEALTHY
    assert len(first.evidence_ids) == 4
    assert len(set(first.evidence_ids)) == 4
    assert first.findings == second.findings
    assert first.diagnosis is None
    assert len(runtime.store.list_for_investigation(first.investigation.investigation_id)) == 4
    assert [event.result for event in runtime.audit.events] == [AuditResult.SUCCESS] * 4

    rendered = render_investigation_report(first)
    assert "Evidence collected:\n4" in rendered
    assert "Findings:" in rendered
    assert "Diagnosis:" in rendered
    assert "INSUFFICIENT" in rendered
    assert "No configuration changes were made" in rendered
    assert "show system" not in rendered
    assert "credential" not in rendered.casefold()


@pytest.mark.asyncio
async def test_high_memory_is_a_critical_finding_not_a_root_cause() -> None:
    runtime = make_runtime(
        healthy_driver(
            health=SystemHealth(
                device_id=DEVICE_ID,
                status=HealthStatus.UNHEALTHY,
                cpu_percent=12,
                memory_percent=94,
            )
        )
    )
    report = await runtime.investigator.investigate_health(DEVICE_ID)

    high_memory = next(finding for finding in report.findings if finding.code == "high_memory")
    assert high_memory.severity is FindingSeverity.CRITICAL
    assert "94%" in high_memory.summary
    assert report.status is InvestigationStatus.CRITICAL
    assert report.diagnosis is None
    assert "confidence" not in report.model_dump_json().casefold()


@pytest.mark.asyncio
async def test_high_cpu_uses_shared_warning_threshold() -> None:
    runtime = make_runtime(
        healthy_driver(
            health=SystemHealth(
                device_id=DEVICE_ID,
                status=HealthStatus.DEGRADED,
                cpu_percent=75,
                memory_percent=40,
            )
        )
    )
    report = await runtime.investigator.investigate_health(DEVICE_ID)

    high_cpu = next(finding for finding in report.findings if finding.code == "high_cpu")
    assert high_cpu.severity is FindingSeverity.WARNING
    assert report.status is InvestigationStatus.WARNING
    assert report.diagnosis is None


@pytest.mark.asyncio
async def test_successful_empty_route_state_confirms_missing_default_route() -> None:
    runtime = make_runtime(healthy_driver(routes=()))
    report = await runtime.investigator.investigate_default_route(DEVICE_ID)

    assert report.status is InvestigationStatus.WARNING
    assert len(report.evidence_ids) == 1
    assert not report.failures
    assert report.findings[0].code == "missing_default_route"
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.CONFIRMED
    assert report.diagnosis.evidence_ids == report.evidence_ids
    evidence = runtime.store.get(report.evidence_ids[0])
    assert isinstance(evidence.payload, RoutesEvidencePayload)
    assert evidence.payload.routes == ()


@pytest.mark.asyncio
async def test_failed_route_collection_produces_partial_insufficient_report() -> None:
    driver = FakeDriver(
        facts=facts(),
        interfaces=(interface(),),
        system_health=SystemHealth(device_id=DEVICE_ID, status=HealthStatus.HEALTHY),
    )
    runtime = make_runtime(
        driver,
        capabilities=driver.capabilities.union({Capability.ROUTES}),
    )
    report = await runtime.investigator.investigate_health(DEVICE_ID)

    assert report.status is InvestigationStatus.INSUFFICIENT
    assert len(report.evidence_ids) == 3
    assert len(report.failures) == 1
    assert report.failures[0].operation == "get_routes"
    assert report.failures[0].error_type == "UnsupportedCapabilityError"
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.INSUFFICIENT
    assert report.diagnosis.missing_evidence == ("route table could not be collected",)
    assert runtime.audit.events[-1].result is AuditResult.FAILURE
    rendered = render_investigation_report(report)
    assert "Missing evidence:\n- route table could not be collected" in rendered
    assert "UnsupportedCapabilityError" not in rendered


@pytest.mark.asyncio
async def test_inventory_unsupported_capability_is_missing_evidence_not_empty_state() -> None:
    runtime = make_runtime(FakeDriver(facts=facts()))
    report = await runtime.investigator.investigate_default_route(DEVICE_ID)

    assert report.evidence_ids == ()
    assert len(report.failures) == 1
    assert report.failures[0].error_type == "UnsupportedDeviceCapabilityError"
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.INSUFFICIENT


@pytest.mark.asyncio
async def test_unauthorized_diagnostic_is_captured_without_evidence() -> None:
    destination = ip_address("198.51.100.10")
    driver = FakeDriver(
        ping_results={
            destination: PingResult(
                device_id=DEVICE_ID,
                destination=destination,
                packets_transmitted=1,
                packets_received=1,
                packet_loss_percent=0,
            )
        }
    )
    runtime = make_runtime(driver)
    result = await runtime.collector.collect(
        investigation_id=UUID(int=100),
        device_id=DEVICE_ID,
        operation="ping",
        capability=Capability.PING,
        arguments={"destination": str(destination)},
    )

    assert isinstance(result, EvidenceCollectionFailure)
    assert result.error_type == "AuthorizationDeniedError"
    assert runtime.store.list_for_investigation(UUID(int=100)) == ()
    assert runtime.audit.events[-1].result is AuditResult.DENIED


@pytest.mark.asyncio
async def test_operationally_down_interface_reports_state_without_cable_claim() -> None:
    runtime = make_runtime(
        healthy_driver(
            interfaces=(
                interface(
                    name="port2",
                    admin=InterfaceState.UP,
                    operational=InterfaceState.DOWN,
                ),
            )
        )
    )
    report = await runtime.investigator.investigate_interface_state(DEVICE_ID, "port2")

    assert report.status is InvestigationStatus.WARNING
    assert report.findings[0].code == "interface_operationally_down"
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.CONFIRMED
    diagnosis_text = report.diagnosis.summary.casefold()
    assert "operationally down" in diagnosis_text
    assert "cause is not known" in diagnosis_text
    assert "unplugged" not in diagnosis_text


@pytest.mark.asyncio
async def test_administratively_down_and_missing_interfaces_are_distinguished() -> None:
    runtime = make_runtime(
        healthy_driver(
            interfaces=(
                interface(
                    name="port3",
                    admin=InterfaceState.DOWN,
                    operational=InterfaceState.DOWN,
                ),
            )
        )
    )
    disabled = await runtime.investigator.investigate_interface_state(DEVICE_ID, "port3")
    assert disabled.findings[0].severity is FindingSeverity.INFO
    assert disabled.diagnosis is not None
    assert disabled.diagnosis.strength is DiagnosisStrength.CONFIRMED

    missing_runtime = make_runtime(healthy_driver(interfaces=(interface(name="port1"),)))
    missing = await missing_runtime.investigator.investigate_interface_state(DEVICE_ID, "port404")
    assert missing.status is InvestigationStatus.INSUFFICIENT
    assert missing.diagnosis is not None
    assert missing.diagnosis.strength is DiagnosisStrength.INSUFFICIENT
    assert missing.diagnosis.missing_evidence


@pytest.mark.asyncio
async def test_ha_healthy_out_of_sync_and_member_missing_findings() -> None:
    healthy = make_runtime(
        FakeDriver(
            ha_status=HAStatus(
                device_id=DEVICE_ID,
                enabled=True,
                health=HealthStatus.HEALTHY,
                members=(
                    HAMember(
                        device_id=DEVICE_ID,
                        member_id="member-a",
                        synchronization=HASynchronizationState.IN_SYNC,
                    ),
                    HAMember(
                        device_id=DEVICE_ID,
                        member_id="member-b",
                        synchronization=HASynchronizationState.IN_SYNC,
                    ),
                ),
            )
        )
    )
    healthy_report = await healthy.investigator.investigate_ha(DEVICE_ID)
    assert healthy_report.status is InvestigationStatus.HEALTHY
    assert healthy_report.findings[0].code == "ha_cluster_healthy"
    assert [event.tool for event in healthy.audit.events] == ["get_ha_status", "get_ha_members"]

    degraded = make_runtime(
        FakeDriver(
            ha_status=HAStatus(
                device_id=DEVICE_ID,
                enabled=True,
                health=HealthStatus.DEGRADED,
                members=(
                    HAMember(
                        device_id=DEVICE_ID,
                        member_id="member-a",
                        synchronization=HASynchronizationState.OUT_OF_SYNC,
                    ),
                ),
            )
        )
    )
    degraded_report = await degraded.investigator.investigate_ha(DEVICE_ID)
    assert {finding.code for finding in degraded_report.findings} == {
        "ha_configuration_out_of_sync",
        "ha_member_count_low",
    }
    assert degraded_report.diagnosis is not None
    assert degraded_report.diagnosis.strength is DiagnosisStrength.CONFIRMED


@pytest.mark.asyncio
async def test_ha_investigation_stages_history_checksum_and_interface_correlation() -> None:
    history = parse_ha_history(
        DEVICE_ID,
        (FIXTURES / "ha_history_repeated_instability.txt").read_text(encoding="utf-8"),
    )
    checksum = parse_ha_checksum_nonsync(
        DEVICE_ID,
        (FIXTURES / "ha_checksum_mismatch.txt").read_text(encoding="utf-8"),
    )
    status = HAStatus(
        device_id=DEVICE_ID,
        enabled=True,
        health=HealthStatus.DEGRADED,
        members=(
            HAMember(
                device_id=DEVICE_ID,
                member_id="member-a",
                synchronization=HASynchronizationState.IN_SYNC,
            ),
            HAMember(
                device_id=DEVICE_ID,
                member_id="member-b",
                synchronization=HASynchronizationState.OUT_OF_SYNC,
            ),
        ),
    )
    runtime = make_runtime(
        FakeDriver(
            ha_status=status,
            ha_history=history,
            ha_checksum_nonsync=checksum,
            interfaces=(interface(name="ha-link-a"),),
        )
    )

    report = await runtime.investigator.investigate_ha(DEVICE_ID)

    assert [event.tool for event in runtime.audit.events] == [
        "get_ha_status",
        "get_ha_members",
        "get_ha_history",
        "get_ha_checksum_nonsync",
        "get_interfaces",
    ]
    assert "event_count=" in runtime.audit.events[2].detail
    assert "mismatch_count=1" in runtime.audit.events[3].detail
    assert report.ha_summary is not None
    assert report.ha_summary.incident_count == 3
    assert report.ha_summary.specific_physical_cause_confirmed is False
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.STRONG
    codes = {finding.code for finding in report.findings}
    assert "ha_configuration_out_of_sync" in codes
    assert "ha_heartbeat_communication_instability" in codes
    assert "ha_heartbeat_link_instability" in codes
    rendered = render_investigation_report(report)
    assert "HA Diagnosis" in rendered
    assert "Specific physical cause:\nNOT CONFIRMED" in rendered


@pytest.mark.asyncio
async def test_ha_unsupported_is_missing_evidence_not_empty_healthy_state() -> None:
    runtime = make_runtime(FakeDriver(), capabilities=frozenset({Capability.HA}))
    report = await runtime.investigator.investigate_ha(DEVICE_ID)
    assert report.status is InvestigationStatus.INSUFFICIENT
    assert report.evidence_ids == ()
    assert report.failures[0].error_type == "UnsupportedCapabilityError"

    truncated_runtime = make_runtime(
        FakeDriver(
            ha_status=HAStatus(
                device_id=DEVICE_ID,
                enabled=True,
                truncated=True,
            )
        )
    )
    truncated = await truncated_runtime.investigator.investigate_ha(DEVICE_ID)
    assert truncated.status is InvestigationStatus.INSUFFICIENT
    assert truncated.diagnosis is not None
    assert truncated.diagnosis.missing_evidence == ("HA member collection was truncated",)


@pytest.mark.asyncio
async def test_sdwan_healthy_member_down_sla_and_alternative_are_deterministic() -> None:
    runtime = make_runtime(
        FakeDriver(
            sdwan_status=SDWANStatus(
                device_id=DEVICE_ID,
                enabled=True,
                members=(SDWANMember(device_id=DEVICE_ID, sequence=1),),
                health_checks=(
                    SDWANHealthCheck(
                        device_id=DEVICE_ID,
                        name="synthetic",
                        member_sequence=1,
                        state=SDWANPathState.ALIVE,
                    ),
                    SDWANHealthCheck(
                        device_id=DEVICE_ID,
                        name="synthetic",
                        member_sequence=2,
                        state=SDWANPathState.DEAD,
                        sla_state=SDWANSLAState.FAILING,
                    ),
                ),
            )
        )
    )
    report = await runtime.investigator.investigate_sdwan(DEVICE_ID)
    codes = {finding.code for finding in report.findings}
    assert codes == {
        "sdwan_member_down",
        "sdwan_sla_failing",
        "sdwan_healthy_alternative",
    }
    assert report.diagnosis is None


@pytest.mark.asyncio
async def test_sdwan_no_healthy_path_and_missing_health_are_distinguished() -> None:
    dead_runtime = make_runtime(
        FakeDriver(
            sdwan_status=SDWANStatus(
                device_id=DEVICE_ID,
                enabled=True,
                health_checks=(
                    SDWANHealthCheck(
                        device_id=DEVICE_ID,
                        name="synthetic",
                        member_sequence=1,
                        state=SDWANPathState.DEAD,
                    ),
                ),
            )
        )
    )
    dead = await dead_runtime.investigator.investigate_sdwan(DEVICE_ID)
    assert dead.diagnosis is not None
    assert dead.diagnosis.strength is DiagnosisStrength.CONFIRMED

    missing_runtime = make_runtime(
        FakeDriver(
            sdwan_status=SDWANStatus(
                device_id=DEVICE_ID,
                enabled=True,
                members=(SDWANMember(device_id=DEVICE_ID, sequence=1),),
            )
        )
    )
    missing = await missing_runtime.investigator.investigate_sdwan(DEVICE_ID)
    assert missing.status is InvestigationStatus.INSUFFICIENT
    assert missing.diagnosis is not None
    assert missing.diagnosis.missing_evidence


@pytest.mark.asyncio
async def test_ipsec_up_phase1_down_phase2_absent_and_interface_correlation() -> None:
    up_runtime = make_runtime(
        FakeDriver(
            interfaces=(interface(name="wan-a"),),
            ipsec_status=IPsecStatus(
                device_id=DEVICE_ID,
                enabled=True,
                phase1=(
                    IPsecPhase1(
                        device_id=DEVICE_ID,
                        name="vpn-a",
                        interface="wan-a",
                        state=IPsecPhaseState.ESTABLISHED,
                    ),
                ),
                tunnels=(
                    IPsecTunnel(
                        device_id=DEVICE_ID,
                        name="vpn-a",
                        interface="wan-a",
                        phase1_state=IPsecPhaseState.ESTABLISHED,
                        phase2=(
                            IPsecPhase2(
                                device_id=DEVICE_ID,
                                name="phase2-a",
                                state=IPsecPhaseState.ESTABLISHED,
                                sa_count=1,
                            ),
                        ),
                    ),
                ),
            ),
        )
    )
    up = await up_runtime.investigator.investigate_ipsec(DEVICE_ID)
    assert up.findings[0].code == "ipsec_tunnels_established"

    down_runtime = make_runtime(
        FakeDriver(
            interfaces=(
                interface(
                    name="wan-b",
                    admin=InterfaceState.UP,
                    operational=InterfaceState.DOWN,
                ),
            ),
            ipsec_status=IPsecStatus(
                device_id=DEVICE_ID,
                enabled=True,
                phase1=(
                    IPsecPhase1(
                        device_id=DEVICE_ID,
                        name="vpn-b",
                        interface="wan-b",
                        state=IPsecPhaseState.DOWN,
                    ),
                ),
                tunnels=(
                    IPsecTunnel(
                        device_id=DEVICE_ID,
                        name="vpn-b",
                        interface="wan-b",
                        phase1_state=IPsecPhaseState.DOWN,
                    ),
                ),
            ),
        )
    )
    down = await down_runtime.investigator.investigate_ipsec(DEVICE_ID)
    assert {finding.code for finding in down.findings} >= {
        "ipsec_phase1_down",
        "ipsec_bound_interface_down",
    }
    assert down.diagnosis is not None
    assert down.diagnosis.strength is DiagnosisStrength.STRONG
    assert len(down.diagnosis.evidence_ids) == 2

    phase2_runtime = make_runtime(
        FakeDriver(
            interfaces=(interface(name="wan-a"),),
            ipsec_status=IPsecStatus(
                device_id=DEVICE_ID,
                enabled=True,
                tunnels=(
                    IPsecTunnel(
                        device_id=DEVICE_ID,
                        name="vpn-c",
                        interface="wan-a",
                        phase1_state=IPsecPhaseState.ESTABLISHED,
                    ),
                ),
            ),
        )
    )
    phase2 = await phase2_runtime.investigator.investigate_ipsec(DEVICE_ID)
    assert phase2.findings[0].code == "ipsec_phase2_missing"


@pytest.mark.asyncio
async def test_dynamic_routing_established_idle_zero_prefix_and_ospf_states() -> None:
    runtime = make_runtime(
        FakeDriver(
            bgp_status=BGPStatus(
                device_id=DEVICE_ID,
                enabled=True,
                neighbors=(
                    BGPNeighbor(
                        device_id=DEVICE_ID,
                        address=ip_address("198.51.100.10"),
                        remote_as=65001,
                        state=BGPSessionState.ESTABLISHED,
                        prefixes_received=0,
                    ),
                    BGPNeighbor(
                        device_id=DEVICE_ID,
                        address=ip_address("203.0.113.10"),
                        remote_as=65002,
                        state=BGPSessionState.IDLE,
                    ),
                ),
            ),
            ospf_status=OSPFStatus(
                device_id=DEVICE_ID,
                enabled=True,
                neighbors=(
                    OSPFNeighbor(
                        device_id=DEVICE_ID,
                        neighbor_id=ip_address("198.51.100.20"),
                        state=OSPFNeighborState.FULL,
                    ),
                    OSPFNeighbor(
                        device_id=DEVICE_ID,
                        neighbor_id=ip_address("203.0.113.20"),
                        state=OSPFNeighborState.INIT,
                    ),
                ),
            ),
        )
    )
    report = await runtime.investigator.investigate_dynamic_routing(DEVICE_ID)
    assert {finding.code for finding in report.findings} == {
        "bgp_neighbor_not_established",
        "bgp_zero_received_prefixes",
        "ospf_neighbor_not_full",
    }
    assert report.diagnosis is not None
    assert report.diagnosis.strength is DiagnosisStrength.CONFIRMED


@pytest.mark.asyncio
async def test_dynamic_routing_none_and_unsupported_produce_explicit_state() -> None:
    none_runtime = make_runtime(
        FakeDriver(
            bgp_status=BGPStatus(device_id=DEVICE_ID, enabled=True),
            ospf_status=OSPFStatus(device_id=DEVICE_ID, enabled=True),
        )
    )
    none = await none_runtime.investigator.investigate_dynamic_routing(DEVICE_ID)
    assert {finding.code for finding in none.findings} == {
        "bgp_no_neighbors",
        "ospf_no_neighbors",
    }

    unsupported_runtime = make_runtime(
        FakeDriver(), capabilities=frozenset({Capability.BGP, Capability.OSPF})
    )
    unsupported = await unsupported_runtime.investigator.investigate_dynamic_routing(DEVICE_ID)
    assert unsupported.status is InvestigationStatus.INSUFFICIENT
    assert len(unsupported.failures) == 2


def test_diagnosis_strength_has_only_qualitative_values() -> None:
    assert {strength.value for strength in DiagnosisStrength} == {
        "confirmed",
        "strong",
        "probable",
        "insufficient",
    }
    assert "confidence" not in InvestigationReport.model_fields
