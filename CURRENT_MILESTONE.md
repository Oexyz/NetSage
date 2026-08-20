# Current Milestone: FortiGate Read-Only Driver

Status: implemented and fixture-verified in the current worktree; authorized live
verification remains before the milestone can be called complete.

This file defines current implementation scope. Long-term architecture and
security requirements remain authoritative in `PROJECT_SPEC.md`.

## Goals

- implement a trusted FortiOS SSH connection lifecycle with mandatory host-key
  validation;
- resolve credentials only inside the transport boundary;
- support a process-memory-only credential provider for bounded live tests;
- expose no raw command or generic SSH surface;
- normalize FortiGate facts, interfaces, VLAN subinterfaces, ARP entries, active
  routes, system health, and IPv4 firewall policies;
- implement fixed, IP-only ping and traceroute diagnostics;
- keep diagnostics denied unless the Observe policy explicitly allows them;
- redact known credentials and secret patterns before output reaches parsers;
- provide a single-connection passive snapshot for live verification;
- provide synthetic sanitized FortiGate fixtures and deterministic tests;
- expose operations through structured, capability-aware Broker tools;
- add an interactive `netsage fortigate live-test` command which never persists
  credentials or raw output.

## Supported capabilities

| Capability | Status | FortiOS command |
|---|---|---|
| Facts | Implemented | `get system status` |
| Interfaces | Implemented | `show system interface`, `get system interface physical` |
| VLANs | Implemented | Parsed from system interface configuration |
| ARP | Implemented | `get system arp` |
| Routes | Implemented | `get router info routing-table all` |
| System health | Implemented | `get system performance status` |
| IPv4 firewall policies | Implemented | `show firewall policy` |
| Ping | Policy-controlled | `execute ping <validated-IP>` |
| Traceroute | Policy-controlled | `execute traceroute <validated-IP>` |
| MAC table | Unsupported | Not simulated |
| LLDP | Unsupported | Not simulated |

## Non-goals

- no configuration changes or automatic remediation;
- no unrestricted SSH, shell, CLI string, or command template supplied by users
  or AI;
- no credential persistence in files, environment variables, shell history,
  inventory, logs, evidence, or audit events;
- no REST transport or API-token support in this milestone;
- no VPN, BGP, OSPF, session-table, or log collection;
- no FortiSwitch or FortiLink implementation;
- no discovery, topology, investigation engine, Web UI, or MCP server;
- no persistent inventory or audit storage.

## Acceptance criteria

- the server host key is discovered without authentication and explicitly pinned
  before a credential is sent;
- authentication errors and command failures contain no raw device output or
  credential material;
- every command is rendered from a closed enum and typed arguments;
- live passwords exist only in process memory for the bounded operation;
- the passive snapshot uses one SSH connection and makes no configuration change;
- paged FortiOS output is collected without changing the global console output mode;
- fixture output is synthetic and contains no real infrastructure data;
- parser incompatibility fails visibly instead of returning fabricated data;
- Broker tools validate devices, capabilities, arguments, authorization, and
  result identity;
- Ruff, strict mypy, pre-commit, and pytest pass;
- an authorized live snapshot succeeds against a real FortiGate before the
  milestone is declared complete.

## Next milestone candidate

After live verification, add a typed evidence envelope and expose the first
FortiGate observations to a deterministic investigation workflow. Do not add an
AI provider until evidence provenance and persistent audit requirements are
defined.
