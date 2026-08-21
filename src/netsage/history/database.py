"""SQLite connection, schema, integrity, and transaction lifecycle."""

import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

HISTORY_SCHEMA_VERSION = 1
_REQUIRED_TABLES = frozenset({"investigations", "evidence", "audit_events"})


class HistoryError(RuntimeError):
    pass


class HistorySchemaError(HistoryError):
    pass


class HistoryCorruptError(HistoryError):
    pass


class HistoryPersistenceError(HistoryError):
    pass


class HistoryDatabase:
    """Own SQLite setup and fail closed on unsupported or damaged history."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def initialize(self) -> None:
        created = not self.path.exists()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if os.name != "nt":
            self.path.parent.chmod(0o700)
        try:
            connection = sqlite3.connect(self.path)
            try:
                connection.execute("PRAGMA foreign_keys = ON")
                connection.execute("PRAGMA synchronous = FULL")
                if created:
                    self._create_schema(connection)
                else:
                    self._validate_schema(connection)
            finally:
                connection.close()
        except sqlite3.DatabaseError as error:
            raise HistoryCorruptError("NetSage history database is invalid") from error
        if os.name != "nt":
            self.path.chmod(0o600)

    def connect(self) -> sqlite3.Connection:
        if not self.path.exists():
            raise HistorySchemaError("NetSage history database is missing; run netsage setup")
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(self.path)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            self._validate_schema(connection)
            return connection
        except Exception as error:
            if connection is not None:
                connection.close()
            if isinstance(error, HistoryError):
                raise
            if isinstance(error, sqlite3.DatabaseError):
                raise HistoryCorruptError("NetSage history database is invalid") from error
            raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def quick_check(self) -> str:
        connection = self.connect()
        try:
            row = connection.execute("PRAGMA quick_check").fetchone()
        except sqlite3.DatabaseError as error:
            raise HistoryCorruptError("NetSage history integrity check failed") from error
        finally:
            connection.close()
        if row is None or str(row[0]) != "ok":
            raise HistoryCorruptError("NetSage history integrity check failed")
        return "ok"

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            BEGIN;
            CREATE TABLE investigations (
                investigation_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT NOT NULL,
                status TEXT NOT NULL,
                target_interface TEXT,
                report_json TEXT NOT NULL
            );
            CREATE TABLE evidence (
                evidence_id TEXT PRIMARY KEY,
                investigation_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                operation TEXT NOT NULL,
                capability TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                envelope_json TEXT NOT NULL,
                FOREIGN KEY (investigation_id)
                    REFERENCES investigations(investigation_id) ON DELETE CASCADE
            );
            CREATE TABLE audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                user TEXT NOT NULL,
                ai_provider TEXT,
                tool TEXT NOT NULL,
                device TEXT,
                safe_arguments_json TEXT NOT NULL,
                result TEXT NOT NULL,
                duration_ms REAL NOT NULL CHECK (duration_ms >= 0),
                authorization_json TEXT NOT NULL,
                configuration_changed INTEGER NOT NULL DEFAULT 0 CHECK (configuration_changed = 0),
                credential_exposed INTEGER NOT NULL DEFAULT 0 CHECK (credential_exposed = 0),
                detail TEXT
            );
            CREATE INDEX investigations_device_idx ON investigations(device_id);
            CREATE INDEX investigations_started_idx ON investigations(started_at);
            CREATE INDEX evidence_investigation_idx ON evidence(investigation_id);
            CREATE INDEX audit_timestamp_idx ON audit_events(timestamp);
            CREATE INDEX audit_device_idx ON audit_events(device);
            PRAGMA user_version = 1;
            COMMIT;
            """
        )

    @staticmethod
    def _validate_schema(connection: sqlite3.Connection) -> None:
        version_row = connection.execute("PRAGMA user_version").fetchone()
        version = int(version_row[0]) if version_row is not None else 0
        if version != HISTORY_SCHEMA_VERSION:
            raise HistorySchemaError(
                "NetSage history database uses unsupported schema version "
                f"{version}; this installation supports version {HISTORY_SCHEMA_VERSION}"
            )
        rows = connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
        tables = {str(row[0]) for row in rows}
        missing = _REQUIRED_TABLES.difference(tables)
        if missing:
            raise HistorySchemaError("NetSage history database schema is incomplete")
