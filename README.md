<h1 align="center">NetSage</h1>

<p align="center">
  Investigate networks. Expose evidence, not credentials.<br>
  A provider-agnostic foundation for secure, read-only AI-assisted network diagnostics.
</p>

<p align="center">
  <img alt="CI configured" src="https://img.shields.io/badge/CI-configured-2088FF?logo=githubactions&logoColor=white">
  <img alt="Python 3.13" src="https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white">
  <img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-f59e0b">
  <a href="LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-2ea44f"></a>
</p>

NetSage is an open-source **AI Network & Infrastructure Investigator**. It is
designed around isolated credentials, allowlisted device operations, sanitized
evidence, and interchangeable AI providers. An AI model may ask for a structured
operation such as `get_interfaces("hp-core-01")`; it must never receive raw SSH,
shell, password, private-key, or API-token access.

> [!IMPORTANT]
> NetSage is currently alpha software. Core security, storage, CLI, Evidence,
> and agent-runtime components are Supported. FortiOS device functionality is
> Beta while compatibility coverage grows. Native Codex OAuth remains
> Experimental because it depends on upstream compatibility behavior. Version
> 0.1 is exclusively read-only and is not production-ready software.

## Capability status

| Status | Area | Current boundary |
|---|---|---|
| Supported | Developer foundation | Python/uv packaging, CI, Ruff, strict mypy, pytest, pre-commit, doctor, and standalone-build foundation |
| Supported | Core security platform | Typed models, capabilities, Inventory contracts, ObservePolicy, SecretRedactor, ToolBroker, and structured tools |
| Supported | Local state, credentials, and SSH trust | Versioned atomic state, isolated OS-keyring secrets, credential profiles, and changed-key rejection |
| Supported | Evidence, History, and Audit | Typed provenance, persistent reports/Evidence, transactions, ephemeral mode, and secret-free append-only Audit |
| Supported | AI boundary and AgentRuntime | Allowlisted AIContext, Broker-owned tools, Evidence validation, hard limits, and deterministic/provider separation |
| Supported | Interactive shell | Shared-handler NetSage REPL with quoting/help/cancellation tests and no OS-shell fallback |
| Beta | FortiGate / FortiOS | Live-verified read-only driver and onboarding; firmware/model compatibility breadth remains limited |
| Beta | Deterministic FortiOS investigations | Health, route, interface, HA, SD-WAN, IPsec, and dynamic-routing workflows |
| Beta | FortiOS semantic compatibility | 14 typed operations, staged HA correlation, reviewed variants, explicit capability states, and a safe compatibility report |
| Beta | FortiOS command knowledge | 19,030 classified FortiOS 7.2.13 definitions; knowledge coverage is not universal FortiOS support |
| Beta | Safe FortiOS catalog execution | 515 bounded READ_ONLY definitions; 362 require review and 172 are non-executable |
| Beta | OpenAI API | Official API-key-backed provider with strict output and isolated keyring storage |
| Beta | Codex App Server | Optional official installed-Codex adapter with managed auth and provider-owned tools denied |
| Experimental | Native Codex OAuth | Live-verified ChatGPT-subscription compatibility path whose upstream contract may change |
| Planned | Additional AI providers | Claude, Ollama, and generic compatible endpoints |
| Planned | Additional vendors | FortiSwitch, Aruba, Cisco, Arista, Juniper, MikroTik, and others |
| Planned | Discovery and topology | Discovery, graph correlation, Vantage Points, and Probes |
| Planned | Apply and product surfaces | Plan/Apply, remediation, MCP, and Web UI |

See [feature maturity levels](docs/status-levels.md) for the definitions and
current decision record. Supported means maintained and tested within the alpha
lifecycle; pre-1.0 compatibility may still evolve, and the label is not a claim
that defects or security bugs are impossible.

## Real-world validation

### Intermittent WAN failure

In a real authorized production vessel network, internet connectivity repeatedly
failed only after several hours of operation. NetSage correlated FortiGate logs,
interface state, historical events, routing and network state, and the timing of
WAN events. In approximately five minutes of analysis, it produced a strong
indication that the likely fault domain was the physical WAN link. A subsequent
manual inspection confirmed the root cause: a faulty WAN cable.

- Approximate NetSage analysis time: **~5 minutes**
- Estimated comparable manual troubleshooting effort: **~3 hours**
- Confirmed root cause: **faulty WAN cable**

This is one operational case, not a controlled benchmark. NetSage is intended to
help experienced administrators correlate large volumes of network observations
and reach the relevant fault domain faster, not replace their judgment or final
physical verification. See the anonymized
[technical case study](docs/case-studies/intermittent-wan-failure.md).

## Security model

NetSage treats device output as untrusted input. The AI-facing boundary exposes
only named tools backed by a trusted Tool Broker and vendor driver. Credentials
are resolved inside the connection layer and must not appear in prompts, logs,
evidence, or tool results.

- Read-only by default, with no v0.1 configuration operations.
- No passwords, SSH private keys, or API tokens in AI context.
- No unrestricted shell or arbitrary device commands for the LLM.
- Structured vendor operations are allowlisted through drivers and the broker.
- Evidence must be sanitized before it crosses the AI boundary.
- Tool calls are designed to become auditable without recording secrets.
- Persistent YAML contains metadata and fingerprints only; passwords remain in
  the OS credential store with no plaintext fallback.

See the [master architecture](PROJECT_SPEC.md), [current milestone](CURRENT_MILESTONE.md),
and complete [security model](SECURITY.md).

The implemented AI boundary is documented in [AI boundary](docs/ai-boundary.md)
and [agent runtime](docs/agent-runtime.md). Provider details are documented for
[native Codex OAuth](docs/providers/openai-codex.md), the optional
[Codex App Server](docs/providers/codex.md), and the separate
[OpenAI API](docs/providers/openai.md). Claude, Ollama, and other real providers
remain unimplemented.

## Quick start for contributors

Install Git, Python 3.13, `uv`, and OpenSSH. Docker is optional for future
integration work. NetSage itself does not require Node.js or Codex CLI. An
existing official Codex installation can be reused optionally.

```powershell
git clone <repository-url> NetSage
cd NetSage
uv sync --dev
uv run netsage --help
uv run netsage doctor
```

Initialize secure user-level state, add a keyring credential and one authorized
FortiOS device, then use its logical Device ID:

```powershell
uv run netsage setup
uv run netsage credentials add
uv run netsage device add
uv run netsage devices
uv run netsage device test fortigate-example
uv run netsage fortios compatibility fortigate-example
uv run netsage investigate fortigate-example
uv run netsage investigate fortigate-example --focus ha
uv run netsage investigations
uv run netsage audit --limit 20
uv run netsage ai codex login
uv run netsage ai status
uv run netsage ask fortigate-example "Check for obvious health or routing issues."
```

Native ChatGPT/Codex OAuth works without a Codex executable or OpenAI API key:

```powershell
netsage ai codex login
netsage ai codex status
netsage ai status
```

For separate usage-based OpenAI Platform access, configure the API provider:

```powershell
netsage ai openai login
netsage ai openai status
netsage ai openai models
```

Device onboarding requires explicit SSH host-key review before authentication.
See [device onboarding](docs/device-onboarding.md),
[credential storage](docs/credentials.md), and [local state](docs/local-state.md).

## Interactive and one-shot use

Start the interactive shell with no arguments. Inside it, omit the repeated
`netsage` prefix:

```text
netsage

netsage> devices
netsage> investigate fortigate-example
netsage> ask fortigate-example "Check routing."
netsage> fortios commands search route
netsage> fortios compatibility fortigate-example
netsage> fortios run fortigate-example fortios.execute.cpu.show --dry-run
netsage> exit
```

The same handlers remain available as one-shot commands for scripts:

```powershell
netsage devices
netsage investigate fortigate-example
netsage ask fortigate-example "Check routing."
netsage fortios commands search route
netsage fortios compatibility fortigate-example --json
netsage fortios run fortigate-example fortios.execute.cpu.show --dry-run
```

The interactive prompt is not a system shell. Unknown inputs such as `whoami`,
`rm`, `cmd`, `powershell`, or `bash` are rejected and never executed. Startup
does not connect to devices or start AI. See [interactive shell](docs/interactive-shell.md).

## Standalone installation

When a tagged GitHub Release exists, its binaries are self-contained and do not
require Python or `uv`. No release asset should be assumed to exist until a `v*`
tag has completed the release workflow successfully.

### Windows

After a release is published, download `netsage-windows-x64.exe` from that GitHub
Release, then run:

```powershell
.\netsage-windows-x64.exe -install
netsage doctor
```

The installer copies the executable to `%LOCALAPPDATA%\NetSage\bin\netsage.exe`
and adds that directory to the current user's `PATH`. It does not request
administrator privileges, install a service, or configure credentials. Open a
new terminal after installation. Release executables are not yet
Authenticode-signed, so Windows may display an unsigned-publisher warning.

To remove its user-level `PATH` entry and installation, run:

```powershell
netsage uninstall-path
```

Windows cannot delete an executable while it is running. When the command is
invoked from the installed copy, it removes the `PATH` entry and prints the
single remaining file to delete after the process exits.

### Linux

Install the binary for the current CPU architecture without `sudo`:

```bash
curl -fsSL https://raw.githubusercontent.com/Oexyz/NetSage/main/install.sh | sh
netsage doctor
```

The script detects Linux x64 or ARM64, downloads the corresponding release and
`SHA256SUMS`, requires a matching SHA-256 checksum, and installs atomically into
`~/.local/bin`. Pin a release with `NETSAGE_VERSION=v0.1.0`. GitHub release
artifacts also receive build-provenance attestations.

Run all local quality gates before submitting a change:

```powershell
uv run ruff format --check .
uv run ruff check .
uv run mypy src
uv run pytest
```

## CLI foundation

```text
netsage --help
netsage --version
netsage doctor
netsage setup
netsage credentials add|list|show|remove
netsage credentials rotate PROFILE
netsage device add|show|test|remove|trust-reset
netsage devices
netsage investigate DEVICE
netsage investigate DEVICE --focus health|ha|sdwan|ipsec|routing
netsage investigate DEVICE --ephemeral
netsage investigations
netsage investigation show|remove UUID
netsage audit --limit N
netsage fortios commands search QUERY
netsage fortios commands show COMMAND_ID
netsage fortios commands coverage
netsage fortios compatibility DEVICE [--json] [--export REPORT.json] [--force]
netsage fortios run DEVICE COMMAND_ID [--arg NAME=VALUE] [--dry-run] [--json]
netsage ai status
netsage ai configure --provider auto|openai-codex|codex-app-server|openai-api
netsage ai codex login|status|logout|import-existing
netsage ai openai status|login|logout|models|configure
netsage ask DEVICE "question"
```

`doctor` reports the local Python, Git, SSH, credential-store, optional Docker,
and selected AI runtime state. Device list/show use only local metadata. Device
test and investigate rediscover and validate stored SSH trust before resolving
the keyring credential and connecting.

Stored Device-ID investigations persist sanitized Report, normalized Evidence,
and safe Audit metadata locally by default. History may contain sensitive network
operational data. It is protected by user-level operating-system permissions, not
application-level SQLite encryption. Use `--ephemeral` when no History should be
written.

The Beta FortiGate live test prompts for every connection value and
keeps its password in process memory only:

```powershell
uv run netsage fortigate live-test
```

It discovers and displays the SSH host-key fingerprint before requesting a
credential, requires explicit process-local trust, collects one passive snapshot,
and persists neither credentials nor raw device output. See [driver details](docs/drivers.md).

The deterministic investigation CLI uses the same secure connection flow and
collects typed evidence exclusively through the Tool Broker:

```powershell
uv run netsage fortigate investigate
```

It produces findings and an optional qualitative diagnosis without an AI
provider. See the [evidence model](docs/evidence.md) and
[investigation semantics](docs/investigations.md).

### Correlated FortiOS HA diagnostics

`netsage investigate DEVICE --focus ha` now starts with cheap HA status/member
Evidence and runs deeper history/checksum diagnostics only after an anomaly. If
heartbeat/member events are present, it correlates the relevant normalized
interface state and reports a bounded fault domain.

The workflow distinguishes confirmed configuration non-synchronization,
probable heartbeat communication instability, strong heartbeat-interface
correlation, explicit member/HA-process restarts, and genuinely insufficient
physical Evidence. It does not equate member rejoin with reboot and never calls
a cable, port, or peer failure confirmed without direct Evidence. Raw HA history,
checksum fingerprints, member identities, and command text are neither persisted
nor sent to AI. See [FortiOS HA diagnostics](docs/fortios-ha-diagnostics.md).

### FortiOS command catalog

The local `fortios.md` reference is processed at development time into a compact
generated runtime manifest. Current measured coverage is:

- 4,972 documented configuration/diagnose/execute topic paths;
- 232 additional complete diagnose/execute syntax paths omitted by those topic lists;
- 13,826 scoped configuration subcommands;
- 55 explicitly accounted PDF conversion/non-command artifacts;
- 19,030 discovered and catalogued definitions (100% generator coverage);
- 1,049 read-only, 2,758 diagnostic, 14,390 configuration, and 833 destructive;
- 515 READ_ONLY definitions safely executable as bounded `SANITIZED_TEXT`;
- 14 additional semantic operations with typed output and Evidence;
- 5 comprehensive semantic status tools exposed through the AI Broker boundary;
- 362 READ_ONLY definitions require review and 172 are non-executable;
- 2 existing IP diagnostic commands plus 2 explicitly reviewed, AI-invisible HA
  diagnostic semantic operations; all other diagnostics remain denied by default;
- 0 configuration and 0 destructive definitions executable;
- 18,513 catalog-only definitions.

This is complete command knowledge, not complete FortiOS execution or parser
support. Configuration/destructive definitions remain denied, the SSH transport
keeps its existing closed allowlist, and the catalog is not exposed wholesale to
AI. Safe expert execution accepts only a logical Device ID, trusted Command ID,
and validated named arguments; output is redacted, bounded, untrusted, audited,
terminal-only, and never automatic Evidence. See
[FortiOS command catalog](docs/fortios-command-catalog.md),
[catalog execution](docs/fortios-catalog-execution.md), and the
[generated coverage report](docs/fortios-command-coverage.md).

The AI-assisted command uses a visible selection policy:

1. configured native `openai-codex` OAuth;
2. optional existing `codex-app-server` authentication;
3. configured `openai-api` key;
4. no AI provider.

Check the effective selection before an investigation:

```powershell
netsage ai status
netsage ask fortigate-example "Check for obvious health or routing issues."
```

Native ChatGPT/Codex OAuth requires neither Codex CLI nor an OpenAI API key:

```powershell
netsage ai codex login
netsage ai codex status
netsage ai status
```

The experimental native provider follows the currently compatible Codex
device-authorization/backend behavior and may require updates when that upstream
behavior changes. Access, refresh, and ID tokens live only in a dedicated OS
keyring entry. They are never sent to the OpenAI Platform API, AIContext, YAML,
History, Audit, Evidence, logs, reports, or terminal output. See
[native Codex OAuth](docs/providers/openai-codex.md).

An installed Codex App Server remains optional. It owns its authentication and
runs ephemeral isolated turns with provider-owned tools disabled and denied.
Native OAuth does not install, invoke, or depend on Codex CLI. An existing
compatible Codex auth file can be imported only after explicit confirmation and
is never modified.

For separate usage-based API access:

```powershell
netsage ai openai login
netsage ai openai status
netsage ask fortigate-example "Check for obvious health or routing issues."
```

Direct API requests require an OpenAI API project/key and may incur separate API
charges. NetSage does not silently turn OAuth/App Server failures into API calls.
Choose a provider explicitly with `netsage ai configure --provider ...` when
automatic selection is not desired.

The API key is validated through the Models API and stored only in its own OS
keyring entry. It never enters YAML, History, Audit, Evidence, logs, or model
context. Every provider receives only sanitized typed Evidence and Broker-owned
tool metadata, uses strict structured output, and exposes no built-in model
tools. Deterministic device and investigation commands work without any AI
authentication. See [OpenAI API provider](docs/providers/openai.md).

## Why the foundation is auditable

| Component | Responsibility | AI receives secrets? |
|---|---|---:|
| Credential Provider | Resolve an opaque profile through the OS keyring inside the trusted runtime boundary | No |
| Network Driver | Translate a fixed read-only operation into vendor-specific access | No |
| Tool Broker | Validate and dispatch allowlisted structured calls | No |
| Evidence layer | Normalize and redact untrusted device output | No |
| AI Provider | Analyze sanitized context and request structured tools | No |

The code deliberately contains no automatic discovery, unrestricted local or
remote shell for AI, network configuration workflow, web dashboard, or NetSage
MCP server. The real AI paths are the experimental native Codex OAuth provider,
optional Codex App Server adapter, and separate OpenAI API provider.

## Current capabilities

### Developer and core platform — supported

- Modern Python 3.13 package managed with `uv`
- CI, Ruff, strict mypy, pytest, pre-commit, doctor, and standalone builds
- Typed vendor-neutral models, capabilities, Inventory, and driver contracts
- ObservePolicy, SecretRedactor, structured Tool Broker, and fake driver

### Interactive shell — supported

- Shared Typer handlers for REPL and one-shot commands
- Tested quoting, nested help, exit/quit, EOF, Ctrl+C, and command equivalence
- Explicit rejection of unknown operating-system commands and no shell fallback

### State, credentials, SSH trust, History, and Audit — supported

- Platform-appropriate versioned YAML with atomic writes and corruption handling
- Separate OS-keyring secrets and transactional CredentialProfile metadata
- Unauthenticated host-key discovery, explicit trust, and changed-key rejection
- Typed transactional SQLite Report/Evidence History and ephemeral mode
- Append-only normal Audit path with no credentials or raw output

### Evidence and agent runtime foundations — supported

- Typed EvidenceEnvelope, UTC provenance, DataTrust, and secret rejection
- Explicit sanitized AIContext and minimal logical-device view
- Broker-owned tools and Evidence-only tool results
- Hard step/tool limits, duplicate detection, safe provider failures, and
  Evidence-backed conclusion validation

### FortiGate read-only driver and onboarding — beta

- Host-key-pinned AsyncSSH transport and credential isolation
- Typed facts, interfaces, VLANs, ARP, routes, health, firewall policies, HA,
  SD-WAN, IPsec, BGP, and OSPF
- Policy-controlled IP-only ping and traceroute
- Live-verified Device-ID onboarding and read-only operations
- Compatibility evidence is concentrated on FortiOS 7.2.13 and a small hardware matrix

### Deterministic FortiOS investigations — beta

- Health, active-default-route, interface-state, HA, SD-WAN, IPsec, and
  dynamic-routing workflows
- Staged HA history/checksum/interface correlation with typed incident episodes
  and an explicit physical root-cause boundary
- Explicit `INSUFFICIENT` results when required observations are unavailable
- AI-independent reports and authorized live verification

### FortiOS semantic observability — beta

- 14 typed operations across HA, SD-WAN, IPsec, BGP, OSPF, and route summary
- Bounded collections with explicit truncation and controlled unsupported output
- Typed Evidence and deterministic findings without raw CLI or invented causes
- Five comprehensive AI tools; focused views remain Broker-only
- Representative HA, disabled SD-WAN, IPsec, and OSPF live verification
- BGP remained missing Evidence on the available target and was not misreported
  as disabled
- Objective readiness remains **KEEP BETA**; see the
  [semantic coverage matrix](docs/fortios-semantic-coverage.md)

### FortiOS semantic compatibility — beta

- Typed `FortiOSVersion` with numeric major/minor/patch range matching plus
  optional build, branch-point, and release metadata
- Explicit Supported, Enabled, Disabled, Not Configured, Unavailable,
  Permission Denied, Output Unrecognized, and Partial states
- At most two reviewed BGP/OSPF variants; fallback occurs only for unavailable,
  empty, or unrecognized output and never for permission, authentication,
  host-key, timeout, or transport failures
- Sequential ten-operation compatibility probe across System, Interfaces,
  Routing, Firewall, HA, SD-WAN, IPsec, BGP, and OSPF
- JSON and atomic file exports are anonymized by default; they contain firmware,
  normalized model family, VDOM category, parser variants, states, and a
  reproducible fingerprint, but no addresses, peers, routes, hostnames, serials,
  credentials, or raw CLI
- Live FortiOS 7.2.13 result: core areas and HA/OSPF parsed, SD-WAN explicitly
  disabled, IPsec partial, and BGP output unrecognized after both reviewed
  variants
- FortiOS remains **Beta**. See the
  [compatibility report and matrix](docs/fortios-compatibility.md).

### FortiOS command knowledge — beta

- Deterministic compressed manifest with 19,030 classified definitions
- 100% of definitions discovered from the FortiOS 7.2.13 source are catalogued
- Local search/info/coverage with no device connection or arbitrary CLI
- Source coverage is not universal FortiOS support or executable coverage

### FortiOS read-only catalog execution — beta

- 515 bounded READ_ONLY commands; 362 require review; 172 are non-executable
- ID-only typed rendering, Observe authorization, redaction, limits, and Audit
- No automatic Evidence/AI exposure, diagnostic promotion, or configuration changes
- Model, firmware, permissions, and `SANITIZED_TEXT` output remain compatibility limits

### OpenAI API — beta

- Official SDK, API-key authentication, model discovery, and strict Structured Outputs
- Separate OS-keyring domain, `store=false`, and no provider-owned tools
- Direct account/model/environment compatibility breadth remains limited

### Codex App Server — beta

- Optional official installed-Codex adapter with Codex-managed authentication
- Ephemeral isolated reasoning, strict output, and provider-owned tools denied
- Live synthetic verification exists, but installation/account coverage is limited

### Native Codex OAuth — experimental

- Live-verified device authorization, keyring storage, refresh, strict inference,
  and complete read-only FortiOS `ask`
- No Codex CLI or API-key requirement and no OAuth/API-key crossover
- Upstream OAuth/backend compatibility is not a guaranteed stable third-party contract

## Roadmap

- Additional AI providers: Claude, Ollama, and generic compatible endpoints
- Additional vendors: FortiSwitch, Aruba, Cisco, Arista, Juniper, MikroTik, and others
- Discovery, topology, Vantage Points, and Probes
- MCP and Web UI after the core remains stable
- Plan/Apply and controlled remediation only after explicit future milestones

## Responsible use

Use NetSage only on systems you own or are authorized to diagnose. Read-only
access still exposes sensitive operational data; apply least privilege, review
device permissions, protect collected evidence, and follow organizational and
vendor policies.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before contributing. New device
operations must be structured, read-only, fixture-tested, and routed through
the Tool Broker. Never commit real credentials or unsanitized production output.

## License

NetSage is open source under the [Apache License 2.0](LICENSE).
