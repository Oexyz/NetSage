# NetSage – Master Architecture & Product Specification

This document defines the long-term product and security architecture of NetSage.
It is not an instruction to implement the entire roadmap at once. The currently
authorized implementation scope is defined by `CURRENT_MILESTONE.md`.

```text
PROJECT_SPEC.md
        │ defines architecture and mandatory boundaries
        ▼
CURRENT_MILESTONE.md
        │ defines current scope
        ▼
Implementation
```

When a milestone conflicts with this specification, document the conflict and
choose the safer design. Never weaken a security boundary silently.

## Product vision

NetSage is an open-source, provider-agnostic AI Network & Infrastructure
Investigator for real multi-vendor environments. It helps network administrators
answer questions such as:

- Why can VLAN 30 not reach the internet?
- Why can `10.20.30.52` not reach `192.168.70.20:443`?
- Where is a given MAC address?
- Why is a port down?
- Which interfaces have CRC errors?
- Trace a VLAN through the network.

NetSage determines the relevant scope, creates an investigation plan, gathers
real network data, normalizes vendor-specific observations, tests hypotheses,
and reports an evidence-backed diagnosis. It is not a chatbot with SSH access.

The intended truthful product pitch is:

> **NetSage is an open-source, provider-agnostic AI network investigator for
> real multi-vendor infrastructure.**
>
> It collects verifiable network evidence through secure vendor drivers while
> keeping device credentials outside the AI context.
>
> **Evidence first. Read-only by default. No network vendor lock-in. No AI
> provider lock-in.**

## Binding product principles

1. **Evidence first.** No unsupported diagnosis.
2. **Read-only by default.** The first stable generation focuses on safe
   investigation, not configuration.
3. **No credential exposure to AI.** Passwords, private keys, tokens, communities,
   and shared secrets never enter AI context.
4. **No unrestricted shell for AI.** The LLM receives structured tools, never a
   generic device or local shell.
5. **No vendor lock-in.** Core behavior uses normalized models and vendor drivers.
6. **No AI-provider lock-in.** Provider adapters remain replaceable.
7. **Honest limitations.** Missing evidence produces `INSUFFICIENT`, not invention.

## Product status and platform priorities

NetSage is in early development. The repository is a tested architecture
foundation, not a production-ready network investigation product.

Initial platform priorities are:

1. FortiGate / FortiOS
2. HP ProCurve and ArubaOS-Switch / AOS-S
3. Aruba AOS-CX
4. FortiSwitch, followed by FortiLink awareness

The architecture must later accommodate Cisco IOS families, Arista EOS, Juniper
Junos, HPE Comware, MikroTik RouterOS, PAN-OS, VyOS, FRRouting, Linux, Proxmox,
and VMware. These integrations must not be added before a concrete milestone.

## Target architecture

```text
                     User
                       │
                       ▼
                CLI / Web / API
                       │
                       ▼
                 NetSage Core
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
        Investigation         Direct
            Engine           Core Query
              │
              ▼
           AI Agent
              │
       Structured Tool Calls
              │
              ▼
         Security Broker
          /     │      \
         /      │       \
 Permissions  Audit   Redaction
         \      │       /
          \     │      /
           Tool Layer
              │
              ▼
          Driver Layer
              │
      Credential Resolution
              │
      ┌───────┼────────┐
      ▼       ▼        ▼
 Fortinet   Aruba    Future
```

The invariant is:

```text
AI → Structured Tools → Security Broker → Vendor Driver
   → Credential Resolution → Device
```

This must never collapse into `AI → SSH + password → device`.

## Security boundary

The AI system must never receive or access:

- device passwords or password hashes;
- SSH private keys or key material;
- API, Vault, or authentication tokens;
- SNMP communities;
- TACACS+ or RADIUS shared secrets;
- authorization headers;
- complete secret stores;
- credential-provider APIs that return raw secrets.

AI-visible devices use logical IDs and non-secret metadata only. Tools such as
`get_password(device)`, `ssh(...)`, `shell(...)`, `run_arbitrary_command(...)`,
or `execute_cli_string(...)` are forbidden in the normal agent tool layer.

Device output is always untrusted data. An interface description containing
prompt-injection text remains an interface description and is never interpreted
as an instruction.

## Security Broker

The Security Broker is the central boundary between AI and infrastructure. A
structured request follows this conceptual pipeline:

```text
device validation
  → authorization
  → capability validation
  → credential resolution
  → driver selection
  → connection
  → redaction
  → normalization
  → audit logging
```

The broker owns the decision. AI input never selects raw commands, bypasses
policy, or resolves credentials. Tool definitions must declare their capability,
operation class, and accepted argument names. Unknown or unexpected arguments,
unknown devices, unknown tools, unsupported capabilities, and denied operations
fail closed.

Normal tools are semantic and structured, for example:

```text
get_device_facts(device)
get_interfaces(device)
get_interface(device, interface)
get_interface_errors(device, interface)
get_vlans(device)
get_mac_table(device)
get_arp_table(device)
get_routes(device)
get_lldp_neighbors(device)
get_system_health(device)
get_firewall_policies(device)
get_bgp_neighbors(device)
get_ospf_neighbors(device)
```

Source-aware diagnostics may later include `ping`, `traceroute`, `tcp_test`, and
`dns_test`, subject to explicit policy and a valid vantage point.

## Capability system

Each driver and inventory device declares only capabilities it actually supports.
Relevant capability families include facts, interfaces, VLANs, MAC table, ARP,
routes, LLDP, system health, firewall, VPN, BGP, OSPF, logs, ping, and traceroute.

Unsupported features must raise a clear error or remain disabled. Returning an
empty result solely to simulate support is forbidden.

## Vendor-neutral models

Drivers normalize vendor-specific data into shared typed models. Implement models
only when required by a current milestone. The long-term domain includes:

- `Device`, `DeviceFacts`, `Interface`, `InterfaceErrors`, `VLAN`, `MacEntry`,
  `ArpEntry`, `Route`, `LldpNeighbor`, and `SystemHealth`;
- `FirewallPolicy`, `BgpNeighbor`, and `OspfNeighbor`;
- `Site`, `DeviceGroup`, `Capability`, and `CredentialReference`;
- `Evidence`, `Diagnosis`, and `Investigation`;
- `VantagePoint` and `Probe`.

Models crossing the AI boundary must be non-secret, normalized, and explicitly
treated as untrusted observations.

## Driver architecture and transports

`NetworkDriver` is an async, vendor-neutral, read-only contract. Its semantic
operations expose facts, interfaces, VLANs, MAC and ARP entries, routes, LLDP
neighbors, and health where supported. Optional functionality is represented by
capabilities, never fake values.

Vendor commands are selected by trusted driver code from fixed, reviewed
operations. The LLM normally does not generate vendor commands. Structured APIs
such as FortiGate REST and AOS-CX REST are preferred where reliable; SSH remains
valid for platforms or observations without a suitable API. The NetSage core
must not depend on whether a driver uses REST, SSH, or a future NETCONF transport.

Every new device operation must be structured, explicitly read-only,
fixture-tested, and routed through the broker.

## Expert raw CLI mode

A separate expert mode may exist later, outside the normal AI tool layer. Commands
must be classified as `READ_ONLY`, `DIAGNOSTIC`, `CONFIGURATION`, or `DESTRUCTIVE`.
For early releases:

| Class | Policy |
|---|---|
| Read-only | Allow through reviewed operations |
| Diagnostic | Explicit policy control |
| Configuration | Deny |
| Destructive | Deny |

No current milestone may introduce generic remote execution.

The current FortiOS command-catalog milestone may model every vendor command,
including configuration and destructive definitions, without making those
definitions executable. Generated catalog knowledge, local search, typed argument
metadata, and policy classification do not weaken the fixed driver/transport
allowlist.

## Credential architecture

Credentials live exclusively in the trusted credential layer. Inventory stores
only an opaque `credential_ref`. Planned providers include OS keychains, SSH
agents, private-key references, and an encrypted local vault. Environment
variables are development-only. Enterprise providers may later include
HashiCorp Vault and major cloud secret managers.

A credential profile can be shared by many devices. Explicit device assignment,
defined credential rules, or a user decision may select it. NetSage must never
try every stored credential against every device.

Larger environments may use centrally managed TACACS+ or RADIUS accounts. Device
authorization must still apply least privilege: allow required show/diagnostic
operations and deny configuration, reload, erase, user management, and similar
privileges. Security must exist both in NetSage and on the managed device.

## Inventory, onboarding, and discovery

Inventory ultimately models devices, sites, groups, platforms, management
addresses, connection methods, credential references, capabilities, tags, and
metadata. It must never store raw credentials.

Onboarding may later support manual entry, reviewed discovery, and imports from
formats or systems such as YAML, CSV, NetBox, Nautobot, Ansible, Proxmox, and
vCenter.

Discovery is restricted to user-approved management networks. It may use seed
devices and observations such as LLDP, ARP, MAC tables, routes, FortiLink, and
management addresses. It must not aggressively scan outside approved scope.
Discovered devices follow `candidate → fingerprint → review → import`; discovery
never silently makes a candidate productive.

## Topology

The topology engine will build a real graph from LLDP, FortiLink, MAC, ARP,
routes, and interface data, with CDP as a later source. ASCII output is a view of
that graph, not its storage model. Graph correlation must support path, MAC, and
VLAN tracing without treating inference as direct evidence.

## Vantage points and probes

Connectivity evidence is meaningful only from a stated source context. A test
from the NetSage management VLAN does not prove connectivity from another VLAN.

Long-term `VantagePoint` types include `netsage_server`, `probe`, `linux_agent`,
`network_device`, and `firewall_interface`. Source selection preference is:

1. endpoint probe;
2. existing server agent;
3. network-device diagnostic context;
4. NetSage server;
5. no suitable vantage point.

Connectivity APIs should require an explicit source, such as:

```python
tcp_test(source="office-cologne", destination="10.30.0.20", port=443)
```

When no suitable source exists, NetSage may inspect configuration, routes,
policies, and topology, but must state that a true endpoint-side test is not
available.

`netsage-probe` is a later restricted diagnostic agent representing a network
perspective. It should connect outbound with strong mutual authentication and
offer only bounded operations such as ping, traceroute, TCP connect, DNS lookup,
gateway, MTU, basic HTTP(S), and local IP information. It must not expose a shell,
filesystem browser, package installer, secret retrieval, or generic execution.

## Investigation engine

The long-term investigation flow is:

```text
User question
  → intent and relevant scope
  → hypotheses
  → investigation plan
  → structured tool execution
  → evidence collection
  → hypothesis evaluation
  → diagnosis
  → human-readable report
```

Hypotheses are not evidence. Missing VLANs, trunk errors, missing routes, firewall
denies, NAT, or DNS problems remain candidates until checked against real data.
Device failures are isolated; one unreachable switch must not crash an entire
investigation.

## Evidence and diagnosis

Evidence is first-class data and records its source device, tool, observation,
and timestamp. Diagnoses reference concrete evidence. Confidence uses qualitative
strength, not invented precision:

- `CONFIRMED`: direct evidence identifies the cause;
- `STRONG`: multiple independent observations support the same cause;
- `PROBABLE`: plausible, but important verification is missing;
- `INSUFFICIENT`: no reliable diagnosis is possible.

A correct `INSUFFICIENT` result lists missing evidence, such as an unreachable
device or absent vantage point. It is always preferable to a fabricated cause.
Every report states that no configuration was changed when operating in observe
mode.

## Core end-to-end use cases

The first high-value scenario is:

```text
FortiGate → HP Core → HP Access → VLAN30 clients
```

with VLAN 30 missing from an uplink trunk. NetSage identifies the VLAN and path,
checks access and core switching, FortiGate interface, gateway, route, firewall
policy and NAT, then points to the missing VLAN with evidence and makes no change.

The second scenario asks why VLAN 20 cannot reach a destination TCP port. If a
VLAN 20 vantage point exists, NetSage correlates its test with the network path
and firewall evidence. It must distinguish VLAN 20 evidence from a test performed
in the management VLAN.

Other long-term queries include MAC and VLAN traces, down or flapping interfaces,
CRC errors, missing VLANs, missing LLDP neighbors, failed BGP sessions, DNS reachability,
and possible single points of failure.

## Raw output, redaction, and prompt injection

The preferred pipeline is:

```text
Device → raw output → secret redaction → parser
       → normalized models → evidence → AI context
```

Where possible, full raw CLI output never reaches AI. Redaction must recognize
passwords and hashes, API keys, bearer tokens, authentication headers, SNMP
communities, TACACS+/RADIUS secrets, private keys, and known token formats.
Known secrets must be removed before AI context, evidence, logs, or audit storage.

Sanitization does not make device text trustworthy. Prompt-like text in a
hostname, description, banner, log, or other field remains untrusted data.

## Audit logging

Relevant tool calls must become auditable without recording credentials or raw
secret-bearing output. An audit event includes timestamp, user, AI provider,
tool, device, safe arguments, result, duration, authorization decision,
`configuration_changed`, and `credential_exposed`. Early implementations may use
an in-memory sink; persistence is a later milestone.

Audit code records safe error categories, not arbitrary exception strings that
could contain secrets.

## AI providers and runtime

AI provider adapters and the agent runtime are separate concepts. All providers
use the same broker boundary. Implemented experimental OpenAI-backed paths are:

- the OpenAI API through officially supported SDKs and API authentication;
- an explicitly requested Codex adapter through the official installed App
  Server and Codex-managed authentication.

Planned additional providers include:

- Anthropic API, with Bedrock and Vertex AI later;
- Ollama, then vLLM, LM Studio, and compatible endpoints.

Browser-token extraction, custom OAuth hacks, and unofficial subscription
credential reuse are forbidden. A deterministic `FakeAIProvider` is required
before investigation tests depend on provider behavior.

The direct provider uses the official OpenAI Python SDK and API-key
authentication. When the official Codex executable is installed, NetSage
instead prefers the documented App Server and lets Codex own its managed
authentication lifecycle. NetSage never reads, copies, serializes, or returns
Codex tokens or auth files. Provider authentication remains separate from
network-device credentials and never enters AIContext.

Neither path exposes provider-owned tools. The Codex adapter uses ephemeral
threads, a scrubbed child environment, an empty temporary working directory,
disabled built-in tool features, read-only/no-tool-network sandboxing, and
protocol-level denial of tool requests. The NetSage AgentRuntime and Tool Broker
remain the only owners of evidence-gathering execution. Browser-token extraction,
browser cookies, and undocumented OAuth flows remain forbidden.

Simple structured queries such as devices, device details, and interfaces do not
require an LLM. AI is reserved for natural language, planning, hypotheses,
correlation, diagnosis, and explanation. Multi-model second opinions remain a
future option and must never bypass the broker.

## Sites, history, and failure handling

Devices and vantage points belong to sites. Investigation history may later store
questions, users, sites, devices, plans, tool calls, evidence, diagnosis,
strength, provider, and proposed remediation—never credentials.

Network operations should eventually support bounded concurrency, global limits,
per-device locking, timeouts, retries, and backoff. Avoid login storms and all
credential-bruteforce behavior. Unreachable devices become explicit missing
evidence rather than fatal global failures.

## Security modes and remediation

Long-term modes are:

- **Observe**: read only; the default and current product mode.
- **Plan**: read and propose exact changes without execution.
- **Apply**: only much later, with explicit human approval and controlled drivers.

No early release performs automatic remediation. A future change engine must
collect current state, back up configuration, generate and validate an exact
change, show it to the user, require explicit approval, execute through a driver,
run post-checks, show before/after differences, and roll back where possible.
There is never a direct LLM-to-CLI path.

## CLI, MCP, and web boundaries

NetSage is CLI-first. Commands are implemented only when their workflow exists;
placeholders must not be described as functional. The current interactive shell
reuses the same registered one-shot CLI handlers and never forwards unknown input
to an operating-system shell. Future commands may cover discovery, topology,
probes, and controlled configuration only in their respective milestones.

An MCP server and Web UI are deferred until the core and drivers are stable. MCP
tools will use the same Security Broker and can never return credentials. No
frontend toolchain or local API service should be introduced without a concrete
milestone.

## Testability and fixtures

Every important layer must be testable without real hardware or paid AI calls.
The architecture should provide deterministic fakes for drivers, credentials, AI,
probes, and transports as their milestones arrive.

Vendor fixtures belong under:

```text
tests/fixtures/
├── fortigate/
├── fortiswitch/
├── aruba_aoss/
└── aruba_aoscx/
```

Fixtures must be synthetic or sanitized and contain no real hostnames, usernames,
addresses, serial numbers, tokens, keys, or customer data. CI never depends on
real network hardware.

Security tests must cover, as relevant to implemented layers:

- credentials never reaching AI context or audit logs;
- configuration and destructive operations denied in observe mode;
- unknown devices and unsupported capabilities rejected;
- prompt-injection content treated as data;
- secrets redacted from raw output.

## Repository architecture

The long-term package areas are:

```text
src/netsage/
├── cli/
├── agent/
├── ai/providers/
├── broker/
├── credentials/
├── discovery/
├── drivers/
├── evidence/
├── incidents/
├── inventory/
├── models/
├── policies/
├── probes/
├── security/
├── tools/
├── topology/
└── vantage/
```

Do not create empty packages merely to mirror this target. Add an area when a
current milestone gives it a real responsibility and tests.

## Phased roadmap

0. **Bootstrap:** Python/uv, package, CLI, tests, quality gates, CI.
1. **Core models and broker:** normalized models, capabilities, inventory,
   credential references, authorization, audit, redaction, and fake driver.
2. **FortiGate:** read-only facts, interfaces, routes, ARP, health, firewall, and
   safe diagnostics, delivered incrementally.
3. **HP / ArubaOS-Switch:** facts, interfaces, VLANs, MAC, LLDP, supported
   ARP/routes, and health.
4. **Aruba AOS-CX:** REST/SSH facts, interfaces, VLAN, MAC, LLDP, routes, health.
5. **FortiSwitch:** basic read-only support, then FortiLink awareness.
6. **AI provider layer:** fake provider, OpenAI API, then explicitly requested
   additional adapters.
7. **Investigation engine:** intent, hypotheses, plans, evidence, diagnosis, report.
8. **Discovery:** approved networks, seeds, LLDP/FortiLink, candidate review,
   credential rules.
9. **Topology:** graph, paths, neighbor correlation, VLAN path.
10. **Vantage points:** source-aware diagnostics and device contexts.
11. **Probe:** secure outbound connection and restricted diagnostics.
12. **Additional vendors:** only after the first platforms are reliable.
13. **MCP / Web:** only after the core is stable.
14. **Controlled remediation:** last, with human approval and rollback design.

The roadmap favors reliable FortiGate and HPE/Aruba support over many partial
platforms. Benchmarks and lab scenarios must use reproducible incidents and real
measurements; invented benchmark values are forbidden.

## Definition of done

A feature is complete only when it has:

- an implementation and explicit typing;
- tests, including relevant failure and security paths;
- preserved credential, broker, and read-only boundaries;
- documentation matching actual behavior;
- passing Ruff formatting and linting, strict mypy, and pytest;
- no secrets, real device captures, or misleading support claims.

Before adding a new interface, ask:

```text
Can this leak credentials?
Can this mutate a device?
Can this become arbitrary command execution?
Can untrusted device content become an AI instruction?
Can this write secrets into logs?
Is the capability explicit?
Is it testable without real hardware?
```

If evidence is incomplete, `INSUFFICIENT` is the correct outcome. A false
diagnosis is worse than no diagnosis.
