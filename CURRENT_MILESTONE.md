# Current Milestone: Evidence & Deterministic Investigation Foundation

Status: complete. The typed evidence pipeline and deterministic FortiOS
investigations are unit-, integration-, fixture-, and live-verified against an
authorized FortiOS 7.2.13 device without persisting credentials or raw output.

This file defines current implementation scope. Long-term architecture and
security requirements remain authoritative in `PROJECT_SPEC.md`.

## Goals

- introduce a typed, vendor-neutral evidence envelope;
- preserve source provenance with evidence identifiers and timezone-aware UTC
  timestamps;
- retain explicit `UNTRUSTED_DEVICE_DATA` marking after normalization;
- retain typed normalized payloads for the implemented FortiOS capabilities;
- convert only Broker-validated, redacted `CommandResult` values into evidence;
- provide a secret-rejecting in-memory evidence store;
- model deterministic investigations, findings, optional diagnoses, missing
  evidence, and human-readable reports;
- implement qualitative diagnosis strength using only `CONFIRMED`, `STRONG`,
  `PROBABLE`, and `INSUFFICIENT`;
- implement deterministic FortiOS investigations for system health, active IPv4
  default route, and interface state;
- distinguish a successfully observed empty state from collection failure;
- isolate tool failures so partial evidence can still produce an honest report;
- keep every device collection routed through the Tool Broker;
- add thorough unit, security, and hardware-free end-to-end tests;
- provide a minimal interactive FortiGate investigation CLI without an AI
  dependency or a second credential/SSH stack.

## Supported evidence inputs

- device facts;
- interfaces;
- VLANs;
- ARP entries;
- routes;
- system health;
- IPv4 firewall policies;
- policy-controlled ping and traceroute results when explicitly authorized.

No new FortiOS command is introduced by this milestone.

## Non-goals

- no AI provider, LLM planning, prompt engine, or external AI dependency;
- no FortiSwitch, HP ProCurve, ArubaOS-Switch, Aruba AOS-CX, Cisco, Arista,
  Juniper, MikroTik, or other new hardware driver;
- no network discovery, LLDP topology engine, multi-device MAC trace, or
  multi-device VLAN trace;
- no NetSage Probe or vantage-point deployment;
- no end-to-end connectivity simulation without a valid vantage point;
- no complex FortiGate firewall-policy simulation;
- no Web UI, FastAPI service, MCP server, Node.js, npm, or frontend;
- no Codex, Claude, Ollama, OpenAI, or other concrete AI provider;
- no automatic remediation, configuration operation, or generic SSH/CLI command;
- no persistent database, ORM, Redis, database cluster, or persistent raw capture;
- no enterprise AAA or credential-store implementation;
- no generic rule engine, workflow engine, or agent framework dependency;
- no topology, discovery, probes, additional vendors, or later roadmap work.

## Acceptance criteria

- evidence payloads remain normalized and typed rather than raw CLI text;
- evidence contains no credential reference, username, password, token, private
  key, SNMP community, auth header, or raw transport material;
- evidence provenance contains only safe device, platform, capability, driver,
  collection-method, and structured-tool metadata;
- every evidence timestamp is timezone-aware and normalized to UTC;
- evidence and investigation models are immutable snapshots where appropriate;
- evidence IDs are unique and diagnoses reference evidence by ID;
- the evidence store accepts only validated, already sanitized envelopes;
- prompt-injection-like device strings remain inert untrusted data;
- audit and evidence remain separate domains;
- route collection failure yields `INSUFFICIENT`, while a successfully collected
  route table with no active IPv4 default route yields a confirmed finding;
- interface analysis reports observed administrative and operational state without
  inventing a cable or hardware cause;
- high CPU and memory are findings, not automatically root-cause diagnoses;
- FakeDriver-to-Broker-to-Evidence-to-Investigation-to-Report and FortiOS fixture
  pipelines are tested end to end;
- the existing `netsage fortigate live-test` continues to work;
- Ruff formatting and linting, strict mypy, pytest, pre-commit, and CLI smoke tests
  pass without lowering the coverage floor;
- no real infrastructure data or credentials are committed.

## Completed previous milestone

The FortiGate read-only driver is implemented, fixture-verified, and its passive
snapshot was live-verified against an authorized FortiOS 7.2.13 device. FortiGate
support remains experimental and is not described as production-ready.

## Next milestone

Not selected. Stop after completing and verifying this milestone; recommend the
next step without beginning AI providers, additional vendors, discovery,
topology, probes, or configuration work.
