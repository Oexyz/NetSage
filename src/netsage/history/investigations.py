"""Transactional typed InvestigationReport persistence and history queries."""

import sqlite3
from collections.abc import Sequence
from datetime import datetime
from typing import Protocol
from uuid import UUID

from pydantic import BaseModel, ConfigDict, ValidationError

from netsage.evidence import EvidenceEnvelope
from netsage.history.database import HistoryDatabase, HistoryPersistenceError
from netsage.history.evidence import SQLiteEvidenceStore
from netsage.history.security import validated_json
from netsage.investigations import (
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.security import SecretRedactor


class InvestigationNotFoundError(LookupError):
    pass


class DuplicateInvestigationError(ValueError):
    pass


class InvestigationSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    investigation_id: UUID
    device_id: str
    kind: InvestigationKind
    started_at: datetime
    completed_at: datetime
    status: InvestigationStatus
    target_interface: str | None = None


class InvestigationStore(Protocol):
    def add(
        self,
        report: InvestigationReport,
        evidence: Sequence[EvidenceEnvelope] = (),
    ) -> None: ...

    def get(self, investigation_id: UUID) -> InvestigationReport: ...

    def list(self, *, limit: int = 50) -> tuple[InvestigationSummary, ...]: ...

    def remove(self, investigation_id: UUID) -> None: ...


class SQLiteInvestigationStore(InvestigationStore):
    def __init__(
        self,
        database: HistoryDatabase,
        *,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._database = database
        self._redactor = redactor or SecretRedactor()
        self._evidence = SQLiteEvidenceStore(database, redactor=self._redactor)

    def add(
        self,
        report: InvestigationReport,
        evidence: Sequence[EvidenceEnvelope] = (),
    ) -> None:
        expected_ids = set(report.evidence_ids)
        actual_ids = {item.evidence_id for item in evidence}
        if expected_ids != actual_ids:
            raise ValueError("report evidence references do not match persisted evidence")
        if any(item.investigation_id != report.investigation.investigation_id for item in evidence):
            raise ValueError("evidence belongs to a different investigation")
        report_json = validated_json(report, self._redactor)
        try:
            with self._database.transaction() as connection:
                self._insert_report(connection, report, report_json)
                for item in evidence:
                    self._evidence._insert(connection, item)
        except sqlite3.IntegrityError as error:
            raise DuplicateInvestigationError("investigation ID already exists") from error

    @staticmethod
    def _insert_report(
        connection: sqlite3.Connection,
        report: InvestigationReport,
        report_json: str,
    ) -> None:
        investigation = report.investigation
        try:
            connection.execute(
                """
                INSERT INTO investigations (
                    investigation_id, device_id, kind, started_at, completed_at,
                    status, target_interface, report_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(investigation.investigation_id),
                    investigation.device_id,
                    investigation.kind.value,
                    investigation.started_at.isoformat(),
                    report.completed_at.isoformat(),
                    report.status.value,
                    investigation.target_interface,
                    report_json,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise DuplicateInvestigationError("investigation ID already exists") from error
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("investigation could not be persisted") from error

    def get(self, investigation_id: UUID) -> InvestigationReport:
        connection = self._database.connect()
        try:
            row = connection.execute(
                "SELECT report_json FROM investigations WHERE investigation_id = ?",
                (str(investigation_id),),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("investigation could not be loaded") from error
        finally:
            connection.close()
        if row is None:
            raise InvestigationNotFoundError("investigation ID was not found")
        try:
            return InvestigationReport.model_validate_json(str(row["report_json"]))
        except ValidationError as error:
            raise HistoryPersistenceError("persisted investigation is invalid") from error

    def list(self, *, limit: int = 50) -> tuple[InvestigationSummary, ...]:
        if limit < 1 or limit > 1000:
            raise ValueError("history limit must be between 1 and 1000")
        connection = self._database.connect()
        try:
            rows = connection.execute(
                """
                SELECT investigation_id, device_id, kind, started_at, completed_at,
                       status, target_interface
                FROM investigations ORDER BY started_at DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("investigations could not be listed") from error
        finally:
            connection.close()
        try:
            return tuple(
                InvestigationSummary(
                    investigation_id=UUID(str(row["investigation_id"])),
                    device_id=str(row["device_id"]),
                    kind=InvestigationKind(str(row["kind"])),
                    started_at=datetime.fromisoformat(str(row["started_at"])),
                    completed_at=datetime.fromisoformat(str(row["completed_at"])),
                    status=InvestigationStatus(str(row["status"])),
                    target_interface=(
                        str(row["target_interface"])
                        if row["target_interface"] is not None
                        else None
                    ),
                )
                for row in rows
            )
        except (ValueError, ValidationError) as error:
            raise HistoryPersistenceError("persisted investigation summary is invalid") from error

    def remove(self, investigation_id: UUID) -> None:
        with self._database.transaction() as connection:
            cursor = connection.execute(
                "DELETE FROM investigations WHERE investigation_id = ?",
                (str(investigation_id),),
            )
            if cursor.rowcount == 0:
                raise InvestigationNotFoundError("investigation ID was not found")
