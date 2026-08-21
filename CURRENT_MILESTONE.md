# Current Milestone: Persistent Investigation History & Audit Foundation

Status: complete. SQLite Report/Evidence history, append-only Broker Audit,
ephemeral mode, doctor checks, and keyring secret rotation are unit-, integration-,
reload-, byte-scan-, and live-verified against an authorized FortiOS 7.2.13
device without credential or raw-output persistence.

## Goals

- add a user-level SQLite history database at the existing NetSage state path;
- use schema version 1, foreign keys, robust transactions, and restrictive files;
- fail closed for corrupt, incomplete, or unsupported database schemas;
- preserve typed EvidenceEnvelope and InvestigationReport roundtrips;
- implement SQLiteEvidenceStore using the existing EvidenceStore contract;
- implement SQLiteInvestigationStore with list, show, remove, and Evidence cascade;
- implement append-only SQLiteAuditSink using the existing AuditSink contract;
- persist Broker audit events independently while an Investigation runs;
- commit completed Investigation Report and Evidence in one transaction;
- make stored Device-ID investigations persistent by default;
- provide an explicit `--ephemeral` mode using in-memory stores only;
- add local History and Audit CLI views without network access;
- extend doctor with passive schema/accessibility/quick-check status;
- add secure keyring secret rotation without changing device configuration;
- defensively reject recognized secret material before every persistent write.

## Non-goals

- no new hardware or driver beyond experimental FortiOS;
- no AI, Codex, Claude, Ollama, OpenAI, MCP, Web UI, or FastAPI;
- no Discovery, Topology, LLDP discovery, probes, or vantage points;
- no device configuration change or password rotation on FortiOS;
- no Vault, cloud secret manager, TACACS+, or RADIUS integration;
- no SQLAlchemy, Alembic, ORM, PostgreSQL, MySQL, Redis, or MongoDB;
- no application-level SQLite encryption claim;
- no automatic cloud sync, telemetry, upload, audit purge, or retention engine;
- no raw CLI output, Credential, keyring secret, or SSH trust duplication in History.

## Security invariants

- History contains sensitive operational data but never credential material;
- History is protected by OS user-level permissions, not database encryption;
- POSIX state directory is 0700 and history file is 0600;
- Audit retains safe arguments and bounded categories, never CommandResult output;
- configuration_changed and credential_exposed remain false;
- known secrets are checked with the existing SecretRedactor before INSERT;
- deleting an Investigation cascades its Evidence but never its Audit events;
- failed final persistence reports the failure and never claims the record was saved.

## Acceptance criteria

- schema, constraints, indexes, quick check, and typed reload are tested;
- unsupported version, invalid SQLite, missing tables, broken JSON, and foreign-key
  errors fail visibly without deleting or replacing the database;
- duplicate Investigation and Evidence IDs become domain errors;
- Report plus Evidence rollback atomically on an injected mid-transaction failure;
- persistent Audit survives failed/final Investigation writes independently;
- normal `netsage investigate DEVICE` persists Report, Evidence, and Audit;
- `netsage investigate DEVICE --ephemeral` creates no history rows;
- list/show/remove and recent Audit CLI work after a new process/store instance;
- keyring secret rotation preserves profile metadata and stores no password history;
- canary secrets are absent from YAML, SQLite bytes, logs, reports, Evidence, Audit,
  and repository files;
- existing FortiOS live-test, interactive investigation, Device test/list, and
  onboarding workflows remain working;
- Ruff, strict mypy, pytest, pre-commit, CLI smokes, and coverage floor pass.

## Completed previous milestones

Secure Local State & Device Onboarding, Evidence & Deterministic Investigation,
and the FortiGate read-only driver are complete and live-verified. FortiGate
support remains experimental.

## Next milestone

Not selected. Stop after completing and verifying this milestone.
