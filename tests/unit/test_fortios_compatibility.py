import asyncio
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from netsage.broker import InMemoryAuditSink, ToolBroker
from netsage.compatibility import (
    CapabilityObservationState,
    CompatibilityArea,
    CompatibilityErrorCategory,
    CompatibilityExportError,
    FortiOSCompatibilityProbe,
    FortiOSCompatibilityReport,
    FortiOSCompatibilityService,
    FortiOSVDOMContext,
    FortiOSVDOMMode,
    export_compatibility_report,
)
from netsage.credentials import CredentialSecretUnavailableError
from netsage.drivers import FakeDriver
from netsage.drivers.fortios import (
    FortiOSCommandUnavailableError,
    FortiOSConnectionError,
    FortiOSPermissionDeniedError,
    FortiOSSemanticErrorCategory,
    FortiOSVariantExhaustedError,
)
from netsage.inventory import Inventory
from netsage.models import (
    BGPStatus,
    DeviceFacts,
    DeviceRef,
    FeatureState,
    FirewallPolicy,
    HAStatus,
    HealthStatus,
    Interface,
    IPsecStatus,
    OSPFStatus,
    RouteSummary,
    SDWANStatus,
    SemanticParserMetadata,
    SemanticParserState,
    SystemHealth,
)
from netsage.tools import StructuredDriverToolSet

NOW = datetime(2026, 8, 22, 12, 0, tzinfo=UTC)
DEVICE_ID = "fortigate-example"


def parser(variant: str, *, partial: bool = False) -> SemanticParserMetadata:
    return SemanticParserMetadata(
        state=SemanticParserState.PARTIAL if partial else SemanticParserState.PARSED,
        variant=variant,
        attempted_variants=(variant,),
    )


def compatible_driver() -> FakeDriver:
    return FakeDriver(
        facts=DeviceFacts(
            device_id=DEVICE_ID,
            vendor="Fortinet",
            model="FortiGate-80F-Synthetic",
            os_version="7.2.13",
            os_build=1762,
            branch_point=1762,
            release="GA",
            vdom="root",
            vdom_configuration="disable",
            max_vdoms=10,
        ),
        interfaces=(
            Interface(
                device_id=DEVICE_ID,
                name="port1",
                admin_state="up",
                operational_state="up",
            ),
        ),
        route_summary=RouteSummary(
            device_id=DEVICE_ID,
            total_routes=1,
            active_routes=1,
            default_routes=1,
            active_default_routes=1,
            protocols=("static",),
        ),
        firewall_policies=(FirewallPolicy(device_id=DEVICE_ID, policy_id=1),),
        system_health=SystemHealth(
            device_id=DEVICE_ID,
            status=HealthStatus.HEALTHY,
        ),
        ha_status=HAStatus(
            device_id=DEVICE_ID,
            enabled=True,
            feature_state=FeatureState.ENABLED,
            parser=parser("ha-status-v1"),
        ),
        sdwan_status=SDWANStatus(
            device_id=DEVICE_ID,
            enabled=True,
            feature_state=FeatureState.ENABLED,
            parser=parser("sdwan-status-v1"),
        ),
        ipsec_status=IPsecStatus(
            device_id=DEVICE_ID,
            enabled=True,
            feature_state=FeatureState.ENABLED,
            parser=parser("ipsec-status-v1"),
        ),
        bgp_status=BGPStatus(
            device_id=DEVICE_ID,
            enabled=True,
            feature_state=FeatureState.ENABLED,
            parser=parser("bgp-summary-v1"),
        ),
        ospf_status=OSPFStatus(
            device_id=DEVICE_ID,
            enabled=True,
            feature_state=FeatureState.ENABLED,
            parser=parser("ospf-neighbor-all-v1"),
        ),
    )


def probe_for(driver: FakeDriver) -> tuple[FortiOSCompatibilityProbe, InMemoryAuditSink]:
    device = DeviceRef(
        name=DEVICE_ID,
        host="192.0.2.1",
        platform="fortios",
        credential_ref="synthetic-readonly",
        capabilities=driver.capabilities,
    )
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=Inventory(devices={device.name: device}),
        audit_sink=audit,
    )
    StructuredDriverToolSet({device.name: driver}).register(broker)
    return (
        FortiOSCompatibilityProbe(
            broker=broker,
            device_id=device.name,
            clock=lambda: NOW,
        ),
        audit,
    )


def area(report: FortiOSCompatibilityReport, name: CompatibilityArea):
    return next(item for item in report.areas if item.area is name)


@pytest.mark.asyncio
async def test_all_supported_report_is_typed_bounded_and_address_free() -> None:
    probe, audit = probe_for(compatible_driver())
    report = await probe.run()

    assert len(report.areas) == 9
    assert len(audit.events) == 10
    assert area(report, CompatibilityArea.SYSTEM).state is CapabilityObservationState.SUPPORTED
    assert area(report, CompatibilityArea.HA).state is CapabilityObservationState.ENABLED
    assert report.firmware is not None
    assert report.firmware.display == "7.2.13"
    assert report.firmware.build == 1762
    assert report.model_family == "FortiGate-80F"
    assert report.vdom.mode is FortiOSVDOMMode.SINGLE
    assert report.vdom.context is FortiOSVDOMContext.ROOT
    assert report.configuration_changed is False
    assert report.raw_cli_included is False
    assert "192.0.2.1" not in report.model_dump_json()


@pytest.mark.asyncio
async def test_disabled_not_configured_and_partial_states_remain_distinct() -> None:
    driver = compatible_driver()
    driver = FakeDriver(
        facts=driver._facts,  # type: ignore[attr-defined]
        interfaces=driver._interfaces,  # type: ignore[attr-defined]
        route_summary=driver._route_summary,  # type: ignore[attr-defined]
        firewall_policies=driver._firewall_policies,  # type: ignore[attr-defined]
        system_health=driver._system_health,  # type: ignore[attr-defined]
        ha_status=HAStatus(
            device_id=DEVICE_ID,
            enabled=False,
            feature_state=FeatureState.DISABLED,
            parser=parser("ha-status-v1"),
        ),
        sdwan_status=SDWANStatus(
            device_id=DEVICE_ID,
            enabled=False,
            feature_state=FeatureState.NOT_CONFIGURED,
            parser=parser("sdwan-status-v1"),
        ),
        ipsec_status=IPsecStatus(
            device_id=DEVICE_ID,
            enabled=None,
            feature_state=FeatureState.UNKNOWN,
            parser=parser("ipsec-status-v1", partial=True),
        ),
        bgp_status=driver._bgp_status,  # type: ignore[attr-defined]
        ospf_status=driver._ospf_status,  # type: ignore[attr-defined]
    )
    report = await probe_for(driver)[0].run()

    assert area(report, CompatibilityArea.HA).state is CapabilityObservationState.DISABLED
    assert area(report, CompatibilityArea.SDWAN).state is CapabilityObservationState.NOT_CONFIGURED
    assert area(report, CompatibilityArea.IPSEC).state is CapabilityObservationState.PARTIAL
    assert (
        area(report, CompatibilityArea.IPSEC).error_category is CompatibilityErrorCategory.PARTIAL
    )


@pytest.mark.asyncio
async def test_vdom_profile_records_categories_without_names() -> None:
    base = compatible_driver()
    assert base._facts is not None  # type: ignore[attr-defined]
    facts = base._facts.model_copy(  # type: ignore[attr-defined]
        update={
            "vdom": "tenant-sensitive-name",
            "vdom_configuration": "enable",
        }
    )
    driver = FakeDriver(
        facts=facts,
        interfaces=base._interfaces,  # type: ignore[attr-defined]
        route_summary=base._route_summary,  # type: ignore[attr-defined]
        firewall_policies=base._firewall_policies,  # type: ignore[attr-defined]
        system_health=base._system_health,  # type: ignore[attr-defined]
        ha_status=base._ha_status,  # type: ignore[attr-defined]
        sdwan_status=base._sdwan_status,  # type: ignore[attr-defined]
        ipsec_status=base._ipsec_status,  # type: ignore[attr-defined]
        bgp_status=base._bgp_status,  # type: ignore[attr-defined]
        ospf_status=base._ospf_status,  # type: ignore[attr-defined]
    )
    report = await probe_for(driver)[0].run()

    assert report.vdom.mode is FortiOSVDOMMode.MULTI
    assert report.vdom.context is FortiOSVDOMContext.SPECIFIC
    assert "tenant-sensitive-name" not in report.model_dump_json()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("error", "expected_state", "expected_category"),
    [
        (
            FortiOSPermissionDeniedError("denied"),
            CapabilityObservationState.PERMISSION_DENIED,
            CompatibilityErrorCategory.PERMISSION_DENIED,
        ),
        (
            FortiOSCommandUnavailableError("unavailable"),
            CapabilityObservationState.UNAVAILABLE,
            CompatibilityErrorCategory.COMMAND_UNAVAILABLE,
        ),
        (
            FortiOSVariantExhaustedError(
                FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
                ("bgp-summary-v1", "bgp-neighbors-v1"),
            ),
            CapabilityObservationState.OUTPUT_UNRECOGNIZED,
            CompatibilityErrorCategory.OUTPUT_UNRECOGNIZED,
        ),
    ],
)
async def test_permission_command_and_parser_failures_are_distinct(
    error: Exception,
    expected_state: CapabilityObservationState,
    expected_category: CompatibilityErrorCategory,
) -> None:
    class FailingDriver(FakeDriver):
        async def get_bgp_status(self) -> BGPStatus:
            raise error

    base = compatible_driver()
    driver = FailingDriver(
        facts=base._facts,  # type: ignore[attr-defined]
        interfaces=base._interfaces,  # type: ignore[attr-defined]
        route_summary=base._route_summary,  # type: ignore[attr-defined]
        firewall_policies=base._firewall_policies,  # type: ignore[attr-defined]
        system_health=base._system_health,  # type: ignore[attr-defined]
        ha_status=base._ha_status,  # type: ignore[attr-defined]
        sdwan_status=base._sdwan_status,  # type: ignore[attr-defined]
        ipsec_status=base._ipsec_status,  # type: ignore[attr-defined]
        bgp_status=base._bgp_status,  # type: ignore[attr-defined]
        ospf_status=base._ospf_status,  # type: ignore[attr-defined]
    )
    report = await probe_for(driver)[0].run()
    result = area(report, CompatibilityArea.BGP)

    assert result.state is expected_state
    assert result.error_category is expected_category
    if isinstance(error, FortiOSVariantExhaustedError):
        assert result.parser_variants == ("bgp-summary-v1", "bgp-neighbors-v1")


@pytest.mark.asyncio
async def test_transport_failure_stops_after_first_operation() -> None:
    class UnreachableDriver(FakeDriver):
        async def get_facts(self) -> DeviceFacts:
            raise FortiOSConnectionError("unreachable")

    driver = UnreachableDriver(facts=compatible_driver()._facts)  # type: ignore[attr-defined]
    probe, audit = probe_for(driver)
    report = await probe.run()

    assert len(audit.events) == 1
    assert all(item.state is CapabilityObservationState.UNAVAILABLE for item in report.areas)
    assert all(
        item.error_category is CompatibilityErrorCategory.TRANSPORT_FAILED for item in report.areas
    )


@pytest.mark.asyncio
async def test_service_returns_typed_report_when_credential_is_unavailable() -> None:
    class Runtime:
        async def prepare(self, _device: DeviceRef):
            raise CredentialSecretUnavailableError("unavailable")

    class State:
        history = object()

        @staticmethod
        def load_inventory() -> Inventory:
            device = DeviceRef(
                name=DEVICE_ID,
                host="192.0.2.1",
                platform="fortios",
                credential_ref="synthetic-readonly",
            )
            return Inventory(devices={device.name: device})

    report = await FortiOSCompatibilityService(
        state=State(),  # type: ignore[arg-type]
        secrets=object(),  # type: ignore[arg-type]
        runtime=Runtime(),  # type: ignore[arg-type]
        clock=lambda: NOW,
    ).inspect(DEVICE_ID)

    assert all(item.state is CapabilityObservationState.UNAVAILABLE for item in report.areas)
    assert all(
        item.error_category is CompatibilityErrorCategory.CREDENTIAL_UNAVAILABLE
        for item in report.areas
    )


@pytest.mark.parametrize(
    "canary",
    [
        "credential-reference-canary",
        "192.0.2.99",
        "oauth-token-canary",
        "openai-api-key-canary",
        "ipsec-secret-canary",
        "198.51.100.99",
    ],
)
def test_anonymized_export_removes_identifiers_and_secrets(
    tmp_path: Path,
    canary: str,
) -> None:
    base = asyncio.run(probe_for(compatible_driver())[0].run())
    unsafe = base.model_copy(update={"device_id": canary})
    target = tmp_path / "compatibility.json"

    export_compatibility_report(unsafe, target)
    content = target.read_text(encoding="utf-8")
    reloaded = FortiOSCompatibilityReport.model_validate_json(content)

    assert canary not in content
    assert reloaded.device_id == "fortios-device"
    assert reloaded.anonymized is True
    assert not re.search(r"(?:\d{1,3}\.){3}\d{1,3}", content)
    with pytest.raises(CompatibilityExportError):
        export_compatibility_report(unsafe, target)
    export_compatibility_report(unsafe, target, force=True)
