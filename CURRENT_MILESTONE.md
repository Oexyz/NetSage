# Current Milestone: Core Architecture

Status: implemented in the current worktree; final review and merge remain.

This file defines current implementation scope. Long-term architecture and
security requirements remain authoritative in `PROJECT_SPEC.md`.

## Goals

- establish the vendor-neutral models required by the existing driver contract;
- implement an explicit capability model;
- implement non-secret inventory, site, and device-group models;
- implement an opaque `CredentialReference` model;
- make the Tool Broker validate tools, declared arguments, devices, capabilities,
  and results;
- implement the default Observe authorization policy;
- implement a secret-free audit event foundation and in-memory sink;
- implement recursive secret-redaction foundations for structured and raw data;
- provide a deterministic `FakeDriver` that fails on unsupported capabilities;
- cover security and failure paths with unit tests.

## Non-goals

- no real device connections or production drivers;
- no configuration changes or automatic remediation;
- no concrete AI provider or investigation engine;
- no broad network discovery;
- no topology engine, vantage-point runtime, or production probe;
- no Web UI or MCP server;
- no Cisco, Arista, Juniper, or other additional vendors;
- no persistent inventory or audit storage.

## Acceptance criteria

- credentials remain outside models returned to AI-facing layers;
- generic SSH, shell, and arbitrary-command tools cannot be registered;
- unknown devices and unsupported capabilities fail closed;
- configuration and destructive operations are denied in Observe mode;
- tool results and audit arguments are redacted;
- audit events never claim credentials were exposed or configuration changed;
- device content is explicitly marked as untrusted data;
- Ruff, strict mypy, and pytest pass.

## Next milestone candidate

Implement the first read-only FortiGate connection lifecycle and `get_facts()`
operation using synthetic sanitized fixtures. Credential resolution must remain
inside the trusted connection boundary, and the operation must be exposed only
through the capability-aware Tool Broker.
