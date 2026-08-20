import logging
from datetime import UTC, datetime
from ipaddress import ip_network
from pathlib import Path
from uuid import UUID

import pytest

from netsage.broker import InMemoryAuditSink, ToolBroker
from netsage.credentials import CredentialProfile
from netsage.drivers import FakeDriver
from netsage.evidence import EvidenceCollector, EvidenceFactory, InMemoryEvidenceStore
from netsage.inventory import Inventory
from netsage.investigations import FortiOSInvestigator, render_investigation_report
from netsage.models import (
    DeviceFacts,
    DeviceRef,
    HealthStatus,
    Interface,
    Route,
    SystemHealth,
)
from netsage.security import SecretRedactor
from netsage.state import LocalState, SSHHostTrustRecord, StatePaths
from netsage.tools import StructuredDriverToolSet

CANARY = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_ANY_BOUNDARY"
NOW = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)


@pytest.mark.asyncio
async def test_canary_absent_from_state_logs_evidence_audit_and_report(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.credentials.add(CredentialProfile(name="fortigate-readonly", username="netsage-ro"))
    state.host_trust.add(
        SSHHostTrustRecord(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            algorithm="ssh-ed25519",
            fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    driver = FakeDriver(
        facts=DeviceFacts(
            device_id="fortigate-example",
            vendor="Fortinet",
            model="Synthetic",
            os_version="test",
        ),
        interfaces=(
            Interface(
                device_id="fortigate-example",
                name="port1",
                admin_state="up",
                operational_state="up",
                description=f"untrusted device note {CANARY}",
            ),
        ),
        routes=(
            Route(
                device_id="fortigate-example",
                prefix=ip_network("0.0.0.0/0"),
                protocol="static",
                selected=True,
            ),
        ),
        system_health=SystemHealth(
            device_id="fortigate-example",
            status=HealthStatus.HEALTHY,
        ),
    )
    device = DeviceRef(
        name="fortigate-example",
        host="192.0.2.10",
        platform="fortios",
        credential_ref="fortigate-readonly",
        trust_ref="fortigate-example",
        capabilities=driver.capabilities,
    )
    state.inventory.add(device)

    reloaded = LocalState(state.paths)
    inventory: Inventory = reloaded.load_inventory()
    redactor = SecretRedactor(known_secrets=(CANARY,))
    audit = InMemoryAuditSink()
    broker = ToolBroker(inventory=inventory, redactor=redactor, audit_sink=audit)
    StructuredDriverToolSet({device.name: driver}).register(broker)
    store = InMemoryEvidenceStore(redactor=redactor)
    evidence_ids = iter(UUID(int=value) for value in range(1, 10))
    collector = EvidenceCollector(
        broker=broker,
        inventory=inventory,
        factory=EvidenceFactory(
            redactor=redactor,
            clock=lambda: NOW,
            evidence_id_factory=lambda: next(evidence_ids),
        ),
        store=store,
        driver="FakeDriver",
        clock=lambda: NOW,
    )
    report = await FortiOSInvestigator(
        collector=collector,
        clock=lambda: NOW,
        investigation_id_factory=lambda: UUID(int=100),
        redactor=redactor,
    ).investigate_health(device.name)

    state_text = "".join(
        path.read_text(encoding="utf-8") for path in state.paths.root.glob("*.yaml")
    )
    evidence_text = "".join(
        item.model_dump_json()
        for item in store.list_for_investigation(report.investigation.investigation_id)
    )
    audit_text = "".join(event.model_dump_json() for event in audit.events)
    report_text = render_investigation_report(report)
    captured_logs = caplog.text
    for serialized in (state_text, evidence_text, audit_text, report_text, captured_logs):
        assert CANARY not in serialized
