from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address, ip_network
from uuid import UUID

import pytest

from netsage.broker import AuditResult, InMemoryAuditSink, ToolBroker
from netsage.drivers import FakeDriver
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
    Capability,
    DeviceFacts,
    DeviceRef,
    HealthStatus,
    Interface,
    InterfaceState,
    PingResult,
    Route,
    SystemHealth,
)
from netsage.tools import StructuredDriverToolSet

NOW = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
DEVICE_ID = "fortigate-lab"


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
    broker = ToolBroker(inventory=inventory, audit_sink=audit, user="test-operator")
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


def test_diagnosis_strength_has_only_qualitative_values() -> None:
    assert {strength.value for strength in DiagnosisStrength} == {
        "confirmed",
        "strong",
        "probable",
        "insufficient",
    }
    assert "confidence" not in InvestigationReport.model_fields
