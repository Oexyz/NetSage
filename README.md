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
| In development | Network platforms | FortiGate, FortiSwitch, HP/HPE/ArubaOS-Switch, and Aruba AOS-CX |
| In development | Security pipeline | Credential-backed connections, persistent audit storage, and evidence collection |
| Planned | AI providers | Codex, Anthropic Claude, Ollama, and OpenAI-compatible APIs |
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

See the [master architecture](PROJECT_SPEC.md), [current milestone](CURRENT_MILESTONE.md),
and complete [security model](SECURITY.md).

## Quick start for contributors

Install Git, Python 3.13, `uv`, and OpenSSH. Docker is optional for future
integration work. Node.js is not required.

```powershell
git clone <repository-url> NetSage
cd NetSage
uv sync --dev
uv run netsage --help
uv run netsage doctor
```

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
```

`doctor` reports the local Python, Git, SSH, credential-store, and optional
Docker state. The `setup`, `device`, and `devices` commands are intentionally
safe placeholders until their read-only workflows are implemented.

## Why the foundation is auditable

| Component | Responsibility | AI receives secrets? |
|---|---|---:|
| Credential Provider | Resolve an opaque credential reference through keychain, SSH agent, or test-only environment provider | No |
| Network Driver | Translate a fixed read-only operation into vendor-specific access | No |
| Tool Broker | Validate and dispatch allowlisted structured calls | No |
| Evidence layer | Normalize and redact untrusted device output | No |
| AI Provider | Analyze sanitized context and request structured tools | No |

The code deliberately contains no automatic discovery, unrestricted remote
shell, network configuration workflow, web dashboard, MCP server, or concrete
AI-agent implementation at this stage.

## Roadmap

### Core architecture — current

- Modern Python 3.13 package managed with `uv`
- CLI and environment doctor
- Typed vendor-neutral models and explicit driver capabilities
- Validated non-secret inventory and opaque credential references
- Observe authorization policy, structured Tool Broker, redaction, and audit events
- Deterministic fake driver for hardware-free tests
- Ruff, mypy, pytest, pre-commit, and GitHub Actions
- Self-contained Windows/Linux release builds and verified user-level installers

### First read-only driver — next

- Trusted FortiGate connection lifecycle
- `get_facts()` with fixture-backed parsing tests
- Credential resolution exclusively inside the trusted connection layer
- Capability-aware broker exposure using normalized `DeviceFacts`

### Vendor and provider expansion — planned

- FortiSwitch, ArubaOS-Switch, and AOS-CX read-only operations
- Codex, Claude, Ollama, and OpenAI-compatible integrations
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
