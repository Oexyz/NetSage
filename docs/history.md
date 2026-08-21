# Persistent Investigation History

NetSage stores sanitized local Investigation history in `history.sqlite3` beside
the existing user-level YAML state. The database uses Python's standard-library
`sqlite3`, schema version 1 (`PRAGMA user_version`), foreign keys, FULL
synchronization, and explicit transactions. No ORM or migration framework is
used.

History contains sensitive operational data such as normalized interfaces,
addresses, routes, VLANs, policies, and health observations. It is protected by
the operating system's user-level file permissions, not application-level
database encryption. NetSage performs no telemetry, upload, or cloud sync.

## Schema

- `investigations`: indexed metadata plus the complete validated report JSON;
- `evidence`: indexed metadata plus the complete validated EvidenceEnvelope JSON;
- `audit_events`: append-only, secret-free Broker audit metadata.

Evidence references its Investigation with `ON DELETE CASCADE`. Deleting an
Investigation removes its Evidence but intentionally retains Audit events.

## Transaction semantics

Broker Audit events are inserted independently as tools run. The completed
InvestigationReport and all matching Evidence are then inserted in one
transaction. A failure rolls the final report and Evidence back together, while
already-written Audit remains available.

Every loaded JSON value is revalidated into its Pydantic domain model. Corrupt
SQLite, unsupported versions, missing tables, broken JSON, duplicate IDs, and
foreign-key violations fail visibly. NetSage never deletes or recreates a damaged
database automatically.

## CLI

```powershell
netsage investigations
netsage investigation show UUID
netsage investigation remove UUID
```

Normal `netsage investigate DEVICE` stores sanitized History locally by default.
Use `--ephemeral` to keep Evidence, Audit, and the Report in memory only.

The current `netsage ask` workflow persists only its Broker Audit events. Its
in-memory Evidence, Agent report, final assessment, and all raw provider protocol
events are not written to History in this milestone.

Manual `fortios run` persists only its secret-free Audit metadata. The bounded
`SANITIZED_TEXT` result is terminal/JSON output and is never inserted into
Investigation, Evidence, or another text-output table.

The complete persistent and ephemeral Device-ID workflows have been live-verified
against an authorized FortiOS 7.2.13 device. Typed Report/Evidence reload, Audit
reload, doctor quick check, unchanged ephemeral row counts, and a direct database
byte scan all succeeded without storing credential material.
