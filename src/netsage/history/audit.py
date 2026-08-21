"""Append-only SQLite AuditSink with typed reload and defensive redaction."""

import json
import sqlite3
from datetime import datetime

from pydantic import JsonValue, TypeAdapter, ValidationError

from netsage.broker import AuditEvent, AuditResult, AuditSink
from netsage.history.database import HistoryDatabase, HistoryPersistenceError
from netsage.history.security import UnsafeHistoryDataError
from netsage.policies import AuthorizationDecision
from netsage.security import SecretRedactor

_SAFE_ARGUMENTS = TypeAdapter(dict[str, JsonValue])


class SQLiteAuditSink(AuditSink):
    """Persist events by INSERT only; no update/delete API is exposed."""

    def __init__(
        self,
        database: HistoryDatabase,
        *,
        redactor: SecretRedactor | None = None,
    ) -> None:
        self._database = database
        self._redactor = redactor or SecretRedactor()

    def record(self, event: AuditEvent) -> None:
        safe_values = {
            "user_value": event.user,
            "provider_value": event.ai_provider,
            "tool_value": event.tool,
            "device_value": event.device,
            "arguments": event.safe_arguments,
            "authorization_reason_value": event.authorization.reason,
            "detail_value": event.detail,
        }
        if self._redactor.redact(safe_values) != safe_values:
            raise UnsafeHistoryDataError("audit event contains recognized secret material")
        if event.timestamp.tzinfo is None or event.timestamp.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        try:
            with self._database.transaction() as connection:
                connection.execute(
                    """
                    INSERT INTO audit_events (
                        timestamp, user, ai_provider, tool, device,
                        safe_arguments_json, result, duration_ms,
                        authorization_json, configuration_changed,
                        credential_exposed, detail
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?)
                    """,
                    (
                        event.timestamp.isoformat(),
                        event.user,
                        event.ai_provider,
                        event.tool,
                        event.device,
                        json.dumps(event.safe_arguments, sort_keys=True),
                        event.result.value,
                        event.duration_ms,
                        event.authorization.model_dump_json(),
                        event.detail,
                    ),
                )
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("audit event could not be persisted") from error

    def list(self, *, limit: int = 50) -> tuple[AuditEvent, ...]:
        if limit < 1 or limit > 1000:
            raise ValueError("audit limit must be between 1 and 1000")
        connection = self._database.connect()
        try:
            rows = connection.execute(
                """
                SELECT timestamp, user, ai_provider, tool, device,
                       safe_arguments_json, result, duration_ms,
                       authorization_json, configuration_changed,
                       credential_exposed, detail
                FROM audit_events ORDER BY id DESC LIMIT ?
                """,
                (limit,),
            ).fetchall()
        except sqlite3.DatabaseError as error:
            raise HistoryPersistenceError("audit events could not be listed") from error
        finally:
            connection.close()
        try:
            return tuple(self._event(row) for row in rows)
        except (ValueError, ValidationError, json.JSONDecodeError) as error:
            raise HistoryPersistenceError("persisted audit event is invalid") from error

    @staticmethod
    def _event(row: sqlite3.Row) -> AuditEvent:
        safe_arguments = json.loads(str(row["safe_arguments_json"]))
        authorization = AuthorizationDecision.model_validate_json(str(row["authorization_json"]))
        return AuditEvent(
            timestamp=datetime.fromisoformat(str(row["timestamp"])),
            user=str(row["user"]),
            ai_provider=str(row["ai_provider"]) if row["ai_provider"] is not None else None,
            tool=str(row["tool"]),
            device=str(row["device"]) if row["device"] is not None else None,
            safe_arguments=_SAFE_ARGUMENTS.validate_python(safe_arguments),
            result=AuditResult(str(row["result"])),
            duration_ms=float(row["duration_ms"]),
            authorization=authorization,
            configuration_changed=False,
            credential_exposed=False,
            detail=str(row["detail"]) if row["detail"] is not None else None,
        )
