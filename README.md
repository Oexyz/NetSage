<h1 align="center">NetSage</h1>

<p align="center">
  Investigate networks. Expose evidence, not credentials.<br>
  A provider-agnostic foundation for secure, read-only AI-assisted network diagnostics.
</p>

<p align="center">
  <img alt="CI configured" src="https://img.shields.io/badge/CI-configured-2088FF?logo=githubactions&logoColor=white">
  <img alt="Python 3.13" src="https://img.shields.io/badge/Python-3.13-3776AB?logo=python&logoColor=white">
  <img alt="Status: early development" src="https://img.shields.io/badge/status-early%20development-f59e0b">
  <a href="LICENSE"><img alt="Apache 2.0 license" src="https://img.shields.io/badge/license-Apache--2.0-2ea44f"></a>
</p>

NetSage is an open-source **AI Network & Infrastructure Investigator**. It is
designed around isolated credentials, allowlisted device operations, sanitized
evidence, and interchangeable AI providers. An AI model may ask for a structured
operation such as `get_interfaces("hp-core-01")`; it must never receive raw SSH,
shell, password, private-key, or API-token access.

> [!IMPORTANT]
> NetSage is in early development. The repository currently provides a tested
> project and security architecture foundation—not production device support.
> Version 0.1 is exclusively read-only; configuration changes are out of scope.

## Capability status

| Status | Area | Current boundary |
|---|---|---|
| Supported | Developer foundation | Installable Python package, CLI, quality gates, and environment diagnostics |
| Supported | Core architecture | Typed network models, capabilities, validated inventory, Observe policy, redaction, in-memory audit events, and fake driver |
| Supported | Core contracts | Network drivers, AI providers, credential isolation, and structured broker tools |
| Experimental | FortiGate | Fixture- and live-verified read-only SSH facts, interfaces, VLANs, ARP, routes, health, firewall policies, ping, and traceroute |
| Experimental | FortiOS command knowledge | Generated 7.2.13 catalog with 19,030 source-derived classified and policy-aware definitions |
| Experimental | FortiOS safe catalog execution | 515 of 1,049 READ_ONLY definitions promoted to bounded, audited `SANITIZED_TEXT`; 362 require review and 172 are non-executable |
| Experimental | Interactive shell | No-argument `netsage` REPL dispatching the same Typer handlers with no OS-shell fallback |
| Experimental | Evidence and deterministic investigations | Typed provenance, in-memory evidence, partial-failure handling, and FortiGate analysis without AI |
| Experimental | Secure local onboarding | Versioned non-secret state, OS-keyring passwords, persistent SSH fingerprint trust, and FortiOS Device-ID workflows |
| Experimental | Persistent history | Local typed Investigation/Evidence history and append-only secret-free Broker Audit in SQLite |
| Experimental | Provider-neutral AI boundary | Sanitized typed context, Broker-owned tools, bounded AgentRuntime, Evidence validation, and FakeAIProvider |
| Experimental | Codex runtime | Installed official Codex App Server, Codex-managed ChatGPT login, isolated ephemeral reasoning, and no provider-owned tools |
| Experimental | OpenAI API fallback | Official Python SDK, hidden API-key setup, OS-keyring isolation, model discovery, Responses API, and structured output when Codex is absent |
| In development | Network platforms | FortiSwitch, HP/HPE/ArubaOS-Switch, and Aruba AOS-CX |
| In development | Security pipeline | Persistent audit and evidence storage |
| Planned | Additional AI providers | Anthropic Claude, Ollama, and compatible endpoints |
| Planned | Additional vendors | Cisco, Arista, Juniper, and others |

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
and [agent runtime](docs/agent-runtime.md). The experimental automatic selection
is documented in [Codex provider](docs/providers/codex.md) and
[OpenAI provider](docs/providers/openai.md). Claude, Ollama, and other real
providers remain unimplemented.

## Quick start for contributors

Install Git, Python 3.13, `uv`, and OpenSSH. Docker is optional for future
integration work. NetSage itself does not require Node.js. An official Codex
installation is optional; when it is absent, NetSage uses the OpenAI API path.

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
uv run netsage investigate fortigate-example
uv run netsage investigations
uv run netsage audit --limit 20
uv run netsage ai status
uv run netsage ask fortigate-example "Check for obvious health or routing issues."
```

If `codex` is installed on `PATH`, authenticate it once using its official flow:

```powershell
codex login
netsage ai status
```

If Codex is not installed, configure the direct API fallback instead:

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
netsage> fortios run fortigate-example fortios.execute.cpu.show --dry-run
netsage> exit
```

The same handlers remain available as one-shot commands for scripts:

```powershell
netsage devices
netsage investigate fortigate-example
netsage ask fortigate-example "Check routing."
netsage fortios commands search route
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
netsage investigate DEVICE --ephemeral
netsage investigations
netsage investigation show|remove UUID
netsage audit --limit N
netsage fortios commands search QUERY
netsage fortios commands show COMMAND_ID
netsage fortios commands coverage
netsage fortios run DEVICE COMMAND_ID [--arg NAME=VALUE] [--dry-run] [--json]
netsage ai status
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

The experimental FortiGate live test prompts for every connection value and
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
- 362 READ_ONLY definitions require review and 172 are non-executable;
- 2 existing structured diagnostic commands with typed parsers; all 2,758
  diagnostics remain denied by default through Catalog Execution;
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

The separate AI-assisted command selects its runtime automatically:

1. If the official `codex` executable exists on `PATH`, NetSage uses
   `codex app-server` and its Codex-managed login.
2. If Codex is absent, NetSage uses the direct OpenAI Responses API fallback.

Check the effective selection before an investigation:

```powershell
netsage ai status
netsage ask fortigate-example "Check for obvious health or routing issues."
```

For the Codex path:

```powershell
codex login
netsage ai status
```

NetSage never reads or copies Codex token files, browser sessions, access tokens,
or refresh tokens. The official App Server owns authentication and refresh. Its
reasoning thread is ephemeral, runs from an empty temporary directory with a
scrubbed environment and read-only/no-network tool sandbox, and receives no
Codex shell, MCP, app, browser, computer-use, or subagent capability. Any
provider-owned tool request fails closed. Codex receives only the same sanitized
typed context that the direct provider receives. See the official
[Codex App Server documentation](https://developers.openai.com/codex/app-server)
and [NetSage Codex adapter](docs/providers/codex.md).

For the direct API fallback when Codex is not installed:

```powershell
netsage ai openai login
netsage ai openai status
netsage ask fortigate-example "Check for obvious health or routing issues."
```

An installed but unauthenticated or incompatible Codex does not silently fall
back to potentially billable API usage; NetSage stops with a bounded error and
asks the user to run `codex login`. Direct API requests require an OpenAI API
project/key and may incur separate API charges. Deterministic device and
investigation commands work without either AI authentication method.

The fallback API key is validated through the Models API and stored only in a
separate OS keyring entry. It never enters YAML, History, Audit, Evidence, logs,
or model context. `ask` sends only sanitized typed Evidence and Broker-owned tool
metadata, sets `store=false`, and enables no OpenAI built-in tools. See
[OpenAI provider](docs/providers/openai.md) for setup and limitations.

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
MCP server. The only real AI paths are the experimental Codex App Server adapter
and direct OpenAI API fallback.

## Roadmap

### Core architecture — complete

- Modern Python 3.13 package managed with `uv`
- CLI and environment doctor
- Typed vendor-neutral models and explicit driver capabilities
- Validated non-secret inventory and opaque credential references
- Observe authorization policy, structured Tool Broker, redaction, and audit events
- Deterministic fake driver for hardware-free tests
- Ruff, mypy, pytest, pre-commit, and GitHub Actions
- Self-contained Windows/Linux release builds and verified user-level installers

### FortiGate read-only driver — complete, experimental

- Host-key-pinned AsyncSSH connection lifecycle
- Prompt-aware collection of paged FortiOS output without changing console settings
- Typed facts, interfaces, VLANs, ARP, routes, health, and firewall policies
- Policy-controlled, IP-only ping and traceroute
- Credential resolution exclusively inside the trusted connection layer
- Capability-aware Broker tools and sanitized synthetic fixtures

### FortiOS CLI coverage and interactive shell — complete

- Deterministic source extractor and compressed, lazily loaded runtime manifest
- 19,030 source-derived definitions with class, capability, arguments, and traceability
- Local search/info/coverage commands with no device connection
- Existing transport allowlist retained; no generic CLI execution
- Interactive no-argument shell over the same Typer command handlers
- Safe quoting, help, exit/quit, EOF/Ctrl+C, and explicit OS-command rejection

### FortiOS read-only catalog execution — current milestone

- Deterministic disposition for all 1,049 READ_ONLY definitions
- 515 promoted one-shot commands; 362 require review; 172 non-executable
- ID-only typed rendering with no arbitrary CLI string surface
- Existing host-key, credential, SSH, paging, timeout, and output-limit reuse
- Mandatory Observe authorization, double redaction, bounded untrusted text, and Audit
- One-shot and REPL `fortios run`, dry-run, and secret-free JSON output
- No AI promotion, Evidence creation, text History, diagnostic auto-promotion, or changes

### Evidence and deterministic investigation — complete

- Typed evidence envelopes with UTC timestamps and non-secret provenance
- Explicit untrusted-data marking and a secret-rejecting in-memory store
- Deterministic FortiGate health, active-default-route, and interface-state checks
- Partial evidence and `INSUFFICIENT` reports when collection fails
- Human-readable reports with no AI dependency

### Secure local state and device onboarding — current milestone, complete

- Platform-appropriate, schema-versioned non-secret YAML state
- Atomic writes, corruption handling, and restrictive user-level permissions
- OS-keyring password profiles with transactional metadata rollback
- Persistent SSH fingerprint trust with changed-key rejection
- FortiOS Device-ID add/list/show/test/remove/investigate workflows
- Credential and Device state remains separate from operational History

### Persistent investigation history and audit — complete

- Standard-library SQLite schema v1 with foreign keys and typed reload
- Transactional Report plus Evidence persistence
- Independent append-only Broker Audit events
- History list/show/remove and recent Audit CLI
- Default persistent and explicit ephemeral Investigation modes
- Defensive SecretRedactor checks before every persistent write

### AI context and agent runtime boundary — complete

- Explicit sanitized AIContext and minimal logical-device view
- Typed Broker-owned tools, calls, results, and provider responses
- Evidence-only tool results with untrusted-data marking
- Hard step/tool budgets and duplicate-call protection
- Evidence-backed final-response and deterministic-contradiction validation
- Deterministic FakeAIProvider for hardware- and API-free tests

### Codex-first OpenAI runtime integration — complete, experimental

- Installed official Codex App Server is preferred and uses Codex-managed auth
- Direct official Python SDK/Responses API fallback only when Codex is absent
- Hidden fallback API-key setup and a provider-specific OS-keyring namespace
- Ephemeral isolated Codex threads with built-in tools disabled and denied
- Authenticated API model discovery and explicit model/effort configuration
- Strict Structured Outputs through the provider-neutral AI contract
- Direct API uses `store=false`; neither path exposes provider-owned tools
- Real `netsage ask`; deterministic `netsage investigate` remains unchanged
- Fake App Server/API clients in CI plus a local synthetic Codex smoke test

### Vendor and provider expansion — planned

- FortiSwitch, ArubaOS-Switch, and AOS-CX read-only operations
- Claude, Ollama, and compatible endpoint integrations
- Further vendors only after the security boundary is proven

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
