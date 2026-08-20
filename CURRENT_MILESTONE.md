# Current Milestone: Secure Local State & Device Onboarding Foundation

Status: complete. Persistent state, OS-keyring credentials, SSH trust, FortiOS
Device-ID workflows, and stored deterministic investigation are unit-,
integration-, reload-, and live-verified against an authorized FortiOS 7.2.13
device without persisting credential material or raw device output.

This file defines current implementation scope. Long-term architecture and
security requirements remain authoritative in `PROJECT_SPEC.md`.

## Goals

- provide persistent, versioned, non-secret user-level application state;
- persist FortiOS device profiles through the existing validated Inventory model;
- introduce serializable credential-profile metadata distinct from Credential;
- store FortiOS SSH passwords only in the operating-system credential store;
- implement the production KeyringCredentialProvider for username/password;
- persist explicit SSH host-key fingerprint trust without storing key material;
- reject missing, mismatched, or changed SSH host identities before authentication;
- implement FortiOS-only device add, list, show, test, remove, and trust reset;
- reuse logical device IDs, CredentialReference, FortiOS transport, Broker,
  Evidence Collector, deterministic investigations, and report rendering;
- support normal repeated use without asking for host, port, username, or password;
- perform atomic state writes and safe corruption/schema handling;
- keep Evidence and Audit in memory.

## Persistent non-secret state

- application settings;
- Inventory and FortiOS device metadata;
- credential-profile provider/kind/username metadata;
- SSH trust host, port, algorithm, and SHA-256 fingerprint.

Passwords, private keys, API tokens, communities, shared secrets, authorization
headers, raw Credential values, raw device output, Evidence, Audit, and
Investigations are never written to these files.

## Non-goals

- no FortiSwitch, HP, Aruba, Cisco, Arista, Juniper, MikroTik, Proxmox, VMware,
  or other new platform;
- no Discovery, Topology, probes, vantage points, MAC/VLAN tracing, or scanning;
- no AI, Codex, Claude, Ollama, OpenAI, MCP, Web UI, REST backend, or FastAPI;
- no automatic remediation or device configuration changes;
- no TACACS+/RADIUS server integration, HashiCorp Vault, or cloud secret manager;
- no SSH-agent implementation in this milestone;
- no development environment password workflow for normal use;
- no persistent Evidence, Investigation, or Audit database;
- no PostgreSQL, Redis, ORM, database, or migration framework;
- no generic SSH, shell, raw CLI, command string, or `shell=True` execution;
- no plaintext credential fallback under any failure condition;
- no credential reveal/get-password command;
- no device-update command or broad non-interactive automation surface.

## Acceptance criteria

- state paths are platform-appropriate and user-level;
- every state document has `schema_version: 1`;
- unknown versions and malformed YAML fail clearly without modifying files;
- writes use a same-directory temporary file, flush/fsync, and atomic replace;
- supported systems receive restrictive user-only file permissions;
- Inventory persists and reloads without mutation or secret fields;
- devices reference existing credential profiles and SSH trust records;
- credential add rolls back the keyring entry if metadata persistence fails;
- keyring/backend errors fail closed without a plaintext fallback;
- credential list/show never reads the secret;
- referenced credential profiles cannot be removed;
- first SSH trust requires explicit confirmation;
- later connections rediscover the public host key before authentication and
  compare algorithm and fingerprint to persistent trust;
- changed host keys abort and are never silently replaced;
- trust reset is a separate explicit confirmation workflow;
- device add authenticates and verifies FortiOS facts before persisting the
  device, with rollback for partial local state writes;
- device list/show perform no network access and disclose no secret;
- device test reports host-key, credential, authentication, FortiOS, and facts
  stages without changing or deleting Inventory when offline;
- device removal removes Inventory and its trust record, but never a shared
  credential profile;
- `netsage investigate DEVICE` uses stored Inventory, keyring credential, SSH
  trust, Broker, Evidence, and deterministic Investigation components;
- existing interactive FortiGate live-test/investigate workflows remain working;
- hardware-free reload tests prove persistence across application instances;
- canary secrets are absent from state files, logs, exceptions, reports, Audit,
  Evidence, Git diff, and committed files;
- Ruff, strict mypy, pytest, pre-commit, CLI smokes, and the coverage floor pass.

## Completed previous milestones

The FortiGate read-only driver and Evidence & Deterministic Investigation
Foundation are complete and live-verified against an authorized FortiOS 7.2.13
device. FortiGate support remains experimental.

## Next milestone

Not selected. Stop after this milestone and recommend the next foundation step
without starting AI providers, additional vendors, Discovery, Topology, probes,
or persistent Evidence/Audit.
