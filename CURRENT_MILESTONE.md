# Current Milestone: FortiOS HA Diagnostic Correlation & Root-Cause Narrowing

Status: complete locally. Publication is valid only when the corresponding
commit is present on `main` and GitHub CI is green.

## Goal

Turn FortiOS HA status, member state, history, checksum non-sync, and relevant
heartbeat-interface observations into bounded typed Evidence and deterministic
fault-domain narrowing.

The intended result distinguishes:

- confirmed configuration synchronization mismatch;
- probable heartbeat communication instability;
- strong heartbeat-interface correlation when independent interface Evidence is
  available;
- explicit member or HA-process restart Evidence;
- unknown or insufficient specific physical cause.

## Delivery

- fixed `get_ha_history` and `get_ha_checksum_nonsync` Broker-only operations;
- individual ObservePolicy promotion for those two diagnostics only;
- bounded `HAEvent`, `HAHistory`, `HAChecksumStatus`, timeline, episode, pattern,
  and fault-domain models;
- device-local/offset-aware timestamp handling without invented timezone;
- deterministic deduplication and a testable five-minute episode window;
- staged `investigate DEVICE --focus ha` collection;
- identity-safe `member-N` references and no raw diagnostic persistence;
- typed History/Checksum Evidence and SQLite roundtrip;
- strengthened AI boundary preventing unsupported diagnosis escalation;
- synthetic regression scenarios for config drift, heartbeat flap, interface
  correlation, member restart, HA-process restart, cause-unknown rejoin, repeated
  incidents, truncation, injection, and secrets;
- read-only authorized live validation and Windows standalone rebuild.

## Security decisions

- no raw HA CLI or caller-provided command string;
- no wildcard `diagnose sys ha *` policy;
- deep HA operations remain `ai_visible=false`;
- raw history, checksum fingerprints, member serials/hostnames, configuration
  values, credentials, and transport exceptions never enter Evidence, History,
  Audit output, or AI context;
- no configuration, force-sync, failover, restart, or remediation operation;
- no physical cable/port/peer cause is confirmed without direct Evidence.

## Non-goals

- no new vendor, AI provider, Discovery, Topology, Vantage Point, Probe, MCP,
  Web, Plan, Apply, or configuration engine;
- no FortiOS Supported promotion from this HA milestone alone;
- no BGP, IPsec, SD-WAN, or OSPF compatibility expansion beyond regression
  preservation.

## Completion evidence required

- staged query-minimization tests and all parser/correlation/security scenarios;
- typed Evidence and backward-compatible SQLite report/evidence loading;
- catalog remains 19,030 total and 515 safe expert executions;
- all non-reviewed diagnostics remain denied; configuration/destructive remain
  non-executable;
- authorized live result correctly reports sync mismatch and heartbeat/member
  correlation while keeping the physical cause unconfirmed;
- `device test` and HA investigation pass from the rebuilt Windows standalone;
- Ruff format/check, strict mypy, pytest/coverage, pre-commit, Markdown,
  secret/vendor-source, Git, push, and GitHub-CI verification.

## Readiness decision

HA semantic diagnostics are **Supported-quality** at the internal typed/parser/
correlation boundary. FortiOS remains **Beta** because firmware/model/VDOM
breadth and separate BGP, IPsec, active SD-WAN, and OSPF gaps remain.

## Verification completed

- Ruff format/check and strict mypy pass for 123 source files;
- 400 tests pass with 87.74% coverage;
- all configured pre-commit hooks pass after their end-of-file normalization;
- generated Catalog remains current at 19,030 definitions and 515 safe expert
  executions;
- authorized source and Windows-standalone `device test` succeed;
- authorized staged HA investigation reports 31 timestamp-correlated incident
  episodes in the collected history window;
- live Findings include confirmed configuration out-of-sync, confirmed
  status/checksum observation disagreement, probable heartbeat communication,
  strong heartbeat-interface correlation, and repeated membership instability;
- no member-restart or HA-process-restart Evidence was observed;
- the specific physical cause remains not confirmed;
- persisted live Evidence contains only HA status, alias-only members, normalized
  history, checksum comparison, and normalized interfaces; raw CLI is absent;
- final Windows artifact size is 26,616,360 bytes with SHA-256
  `4a9c0be50552bf46cba70c1339a932ea71cdec1ea1f21da3438663b0a6799384`;
- no configuration change was made.
