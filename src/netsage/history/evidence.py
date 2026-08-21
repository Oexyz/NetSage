"""Typed SQLite implementation of the EvidenceStore contract."""

import sqlite3
from uuid import UUID

from pydantic import ValidationError

from netsage.evidence import (
    DuplicateEvidenceError,
    EvidenceEnvelope,
    EvidenceNotFoundError,
    EvidenceStore,
)
from netsage.history.database import HistoryDatabase, HistoryPersistenceError
from netsage.history.security import validated_json
from netsage.security import SecretRedactor


class EvidenceForeignKeyError(HistoryPersistenceError):
    pass


class SQLiteEvidenceStore(EvidenceStore):
    def __init__(
        self,
        database: HistoryDatabase,
        *,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._database = database
        self._redactor = redactor or SecretRedactor()

    def add(self, evidence: EvidenceEnvelope) -> None:
        with self._database.transaction() as connection:
            self._insert(connection, evidence)

    def _insert(self, connection: sqlite3.Connection, evidence: EvidenceEnvelope) -> None:
        envelope_json = validated_json(evidence, self._redactor)
        try:
            connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id, investigation_id, device_id, operation,
                    capability, observed_at, envelope_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(evidence.evidence_id),
                    str(evidence.investigation_id),
                    evidence.device_id,
                    evidence.operation,
                    evidence.capability.value,
                    evidence.observed_at.isoformat(),
                    envelope_json,
                ),
            )
        except sqlite3.IntegrityError as error:
            message = str(error).casefold()
            if "foreign key" in message:
                raise EvidenceForeignKeyError(
                    "evidence references an unknown investigation"
                ) from error
            raise DuplicateEvidenceError("evidence ID already exists") from error
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("evidence could not be persisted") from error

    def get(self, evidence_id: UUID) -> EvidenceEnvelope:
        connection = self._database.connect()
        try:
            row = connection.execute(
                "SELECT envelope_json FROM evidence WHERE evidence_id = ?",
                (str(evidence_id),),
            ).fetchone()
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("evidence could not be loaded") from error
        finally:
            connection.close()
        if row is None:
            raise EvidenceNotFoundError("evidence ID was not found")
        try:
            return EvidenceEnvelope.model_validate_json(str(row["envelope_json"]))
        except ValidationError as error:
            raise HistoryPersistenceError("persisted evidence is invalid") from error

    def list_for_investigation(self, investigation_id: UUID) -> tuple[EvidenceEnvelope, ...]:
        connection = self._database.connect()
        try:
            rows = connection.execute(
                """
                SELECT envelope_json FROM evidence
                WHERE investigation_id = ? ORDER BY observed_at, evidence_id
                """,
                (str(investigation_id),),
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("evidence could not be listed") from error
        finally:
            connection.close()
        try:
            return tuple(
                EvidenceEnvelope.model_validate_json(str(row["envelope_json"])) for row in rows
            )
        except ValidationError as error:
            raise HistoryPersistenceError("persisted evidence is invalid") from error
