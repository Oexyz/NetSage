import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest

from netsage.broker import AuditEvent, AuditResult
from netsage.evidence import (
    DuplicateEvidenceError,
    EvidenceEnvelope,
    EvidenceProvenance,
    HAStatusEvidencePayload,
    InterfacesEvidencePayload,
)
from netsage.history import (
    DuplicateInvestigationError,
    EvidenceForeignKeyError,
    HistoryCorruptError,
    HistoryDatabase,
    HistoryPersistenceError,
    HistorySchemaError,
    InvestigationNotFoundError,
    SQLiteAuditSink,
    SQLiteEvidenceStore,
    SQLiteInvestigationStore,
    UnsafeHistoryDataError,
)
from netsage.investigations import (
    Diagnosis,
    DiagnosisStrength,
    Finding,
    FindingSeverity,
    Investigation,
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.models import Capability, DataTrust, HAStatus, Interface, Platform
from netsage.policies import AuthorizationDecision
from netsage.security import SecretRedactor

NOW = datetime(2026, 8, 21, 8, 0, tzinfo=UTC)
INVESTIGATION_ID = UUID(int=100)
EVIDENCE_ID = UUID(int=1)
CANARY = "NETSAGE_PERSISTENCE_CANARY_DO_NOT_STORE_HISTORY"


def make_evidence(description: str = "synthetic uplink") -> EvidenceEnvelope:
    return EvidenceEnvelope(
        evidence_id=EVIDENCE_ID,
        investigation_id=INVESTIGATION_ID,
        device_id="fortigate-example",
        operation="get_interfaces",
        capability=Capability.INTERFACES,
        observed_at=NOW,
        trust=DataTrust.UNTRUSTED_DEVICE_DATA,
        payload=InterfacesEvidencePayload(
            interfaces=(
                Interface(
                    device_id="fortigate-example",
                    name="port1",
                    admin_state="up",
                    operational_state="down",
                    description=description,
                ),
            )
        ),
        provenance=EvidenceProvenance(
            tool="get_interfaces",
            device_id="fortigate-example",
            capability=Capability.INTERFACES,
            platform=Platform.FORTIOS,
            driver="FakeDriver",
        ),
    )


def make_report() -> InvestigationReport:
    return InvestigationReport(
        investigation=Investigation(
            investigation_id=INVESTIGATION_ID,
            device_id="fortigate-example",
            kind=InvestigationKind.FORTIGATE_HEALTH,
            started_at=NOW,
        ),
        completed_at=NOW,
        status=InvestigationStatus.INSUFFICIENT,
        evidence_ids=(EVIDENCE_ID,),
        findings=(
            Finding(
                code="interface_operationally_down",
                title="Interface operationally down",
                summary="Interface port1 is operationally down.",
                severity=FindingSeverity.WARNING,
                evidence_ids=(EVIDENCE_ID,),
            ),
        ),
        diagnosis=Diagnosis(
            summary="More evidence is required.",
            strength=DiagnosisStrength.INSUFFICIENT,
            evidence_ids=(EVIDENCE_ID,),
            missing_evidence=("physical link evidence",),
        ),
    )


def database(tmp_path: Path) -> HistoryDatabase:
    db = HistoryDatabase(tmp_path / "state" / "history.sqlite3")
    db.initialize()
    return db


def test_database_schema_permissions_foreign_keys_and_quick_check(tmp_path: Path) -> None:
    db = database(tmp_path)
    connection = db.connect()
    try:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    finally:
        connection.close()
    assert db.quick_check() == "ok"
    if os.name != "nt":
        assert db.path.stat().st_mode & 0o077 == 0


def test_typed_evidence_and_report_roundtrip_across_store_instances(tmp_path: Path) -> None:
    db = database(tmp_path)
    evidence = make_evidence()
    report = make_report()
    SQLiteInvestigationStore(db).add(report, (evidence,))

    reloaded_report = SQLiteInvestigationStore(HistoryDatabase(db.path)).get(INVESTIGATION_ID)
    reloaded_evidence = SQLiteEvidenceStore(HistoryDatabase(db.path)).get(EVIDENCE_ID)
    listed = SQLiteEvidenceStore(db).list_for_investigation(INVESTIGATION_ID)
    summaries = SQLiteInvestigationStore(db).list()

    assert reloaded_report == report
    assert reloaded_report.findings == report.findings
    assert reloaded_report.diagnosis == report.diagnosis
    assert reloaded_report.diagnosis is not None
    assert reloaded_report.diagnosis.missing_evidence == ("physical link evidence",)
    assert reloaded_evidence == evidence
    assert isinstance(reloaded_evidence.payload, InterfacesEvidencePayload)
    assert reloaded_evidence.observed_at == NOW
    assert reloaded_evidence.trust is DataTrust.UNTRUSTED_DEVICE_DATA
    assert reloaded_evidence.provenance.driver == "FakeDriver"
    assert listed == (evidence,)
    assert summaries[0].investigation_id == INVESTIGATION_ID
    assert summaries[0].status is InvestigationStatus.INSUFFICIENT


def test_semantic_observability_evidence_roundtrips_without_schema_change(
    tmp_path: Path,
) -> None:
    evidence = EvidenceEnvelope(
        evidence_id=EVIDENCE_ID,
        investigation_id=INVESTIGATION_ID,
        device_id="fortigate-example",
        operation="get_ha_status",
        capability=Capability.HA,
        observed_at=NOW,
        trust=DataTrust.UNTRUSTED_DEVICE_DATA,
        payload=HAStatusEvidencePayload(
            status=HAStatus(device_id="fortigate-example", enabled=False)
        ),
        provenance=EvidenceProvenance(
            tool="get_ha_status",
            device_id="fortigate-example",
            capability=Capability.HA,
            platform=Platform.FORTIOS,
            driver="FakeDriver",
        ),
    )
    report = make_report().model_copy(
        update={
            "investigation": make_report().investigation.model_copy(
                update={"kind": InvestigationKind.HA_HEALTH}
            ),
        }
    )
    db = database(tmp_path)
    SQLiteInvestigationStore(db).add(report, (evidence,))

    reloaded = SQLiteEvidenceStore(HistoryDatabase(db.path)).get(EVIDENCE_ID)
    assert reloaded == evidence
    assert isinstance(reloaded.payload, HAStatusEvidencePayload)
    assert reloaded.payload.status.enabled is False


def test_duplicate_ids_unknown_history_delete_and_evidence_cascade(tmp_path: Path) -> None:
    db = database(tmp_path)
    store = SQLiteInvestigationStore(db)
    evidence_store = SQLiteEvidenceStore(db)
    store.add(make_report(), (make_evidence(),))
    with pytest.raises(DuplicateInvestigationError):
        store.add(make_report(), (make_evidence(),))
    with pytest.raises(DuplicateEvidenceError):
        evidence_store.add(make_evidence())
    with pytest.raises(InvestigationNotFoundError):
        store.get(UUID(int=999))

    store.remove(INVESTIGATION_ID)
    assert evidence_store.list_for_investigation(INVESTIGATION_ID) == ()
    with pytest.raises(InvestigationNotFoundError):
        store.remove(INVESTIGATION_ID)


@pytest.mark.parametrize("result", list(AuditResult))
def test_append_only_audit_roundtrip_preserves_safe_semantics(
    tmp_path: Path,
    result: AuditResult,
) -> None:
    db = database(tmp_path)
    sink = SQLiteAuditSink(db)
    allowed = result is AuditResult.SUCCESS
    event = AuditEvent(
        timestamp=NOW,
        user="operator",
        ai_provider=None,
        tool="get_interfaces",
        device="fortigate-example",
        safe_arguments={"device": "fortigate-example"},
        result=result,
        duration_ms=2.5,
        authorization=AuthorizationDecision(allowed=allowed, reason="synthetic decision"),
        detail="bounded detail",
    )
    sink.record(event)
    reloaded = SQLiteAuditSink(HistoryDatabase(db.path)).list(limit=10)
    assert reloaded == (event,)
    assert reloaded[0].configuration_changed is False
    assert reloaded[0].credential_exposed is False
    assert "output" not in reloaded[0].model_dump_json().casefold()


def test_investigation_and_evidence_transaction_rolls_back_on_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = database(tmp_path)
    store = SQLiteInvestigationStore(db)

    def fail_insert(
        _self: SQLiteEvidenceStore,
        _connection: sqlite3.Connection,
        _evidence: EvidenceEnvelope,
    ) -> None:
        raise HistoryPersistenceError("synthetic evidence failure")

    monkeypatch.setattr(SQLiteEvidenceStore, "_insert", fail_insert)
    with pytest.raises(HistoryPersistenceError):
        store.add(make_report(), (make_evidence(),))
    with pytest.raises(InvestigationNotFoundError):
        store.get(INVESTIGATION_ID)


def test_secret_rejected_before_sqlite_bytes_and_no_unused_page_contains_canary(
    tmp_path: Path,
) -> None:
    db = database(tmp_path)
    redactor = SecretRedactor(known_secrets=(CANARY,))
    store = SQLiteInvestigationStore(db, redactor=redactor)
    with pytest.raises(UnsafeHistoryDataError):
        store.add(make_report(), (make_evidence(f"note {CANARY}"),))
    assert CANARY.encode() not in db.path.read_bytes()


def test_foreign_key_invalid_sqlite_unsupported_version_and_missing_tables(
    tmp_path: Path,
) -> None:
    db = database(tmp_path)
    with pytest.raises(EvidenceForeignKeyError):
        SQLiteEvidenceStore(db).add(make_evidence())

    invalid_path = tmp_path / "invalid.sqlite3"
    invalid_path.write_bytes(b"not a sqlite database")
    with pytest.raises(HistoryCorruptError):
        HistoryDatabase(invalid_path).initialize()
    assert invalid_path.read_bytes() == b"not a sqlite database"

    future = tmp_path / "future.sqlite3"
    connection = sqlite3.connect(future)
    connection.execute("PRAGMA user_version = 5")
    connection.close()
    with pytest.raises(HistorySchemaError, match="version 5"):
        HistoryDatabase(future).initialize()

    missing = tmp_path / "missing.sqlite3"
    connection = sqlite3.connect(missing)
    connection.execute("PRAGMA user_version = 1")
    connection.close()
    with pytest.raises(HistorySchemaError, match="incomplete"):
        HistoryDatabase(missing).initialize()


def test_broken_persisted_json_fails_typed_reload(tmp_path: Path) -> None:
    db = database(tmp_path)
    SQLiteInvestigationStore(db).add(make_report(), (make_evidence(),))
    connection = sqlite3.connect(db.path)
    connection.execute(
        "UPDATE investigations SET report_json = ? WHERE investigation_id = ?",
        ("{broken", str(INVESTIGATION_ID)),
    )
    connection.commit()
    connection.close()
    with pytest.raises(HistoryPersistenceError, match="invalid"):
        SQLiteInvestigationStore(db).get(INVESTIGATION_ID)
