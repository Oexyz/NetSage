# NetSage agent guide

This file is the durable handoff for agents working in this repository. Treat the
live source, tests, `SECURITY.md`, and `pyproject.toml` as authoritative when they
conflict with a historical note below.

## Before implementing a feature

1. Read `PROJECT_SPEC.md`.
2. Read `CURRENT_MILESTONE.md` when present.
3. Treat `PROJECT_SPEC.md` as the long-term architecture.
4. Treat `CURRENT_MILESTONE.md` as the current implementation scope.
5. Do not implement future roadmap items without an explicit request.
6. Preserve every mandatory security boundary in `PROJECT_SPEC.md`.
7. Never expose raw credentials to AI contexts, evidence, logs, or tool results.
8. Keep read-only behavior as the default.
9. Add tests for every new behavior and relevant failure path.
10. Update documentation when behavior changes.
11. Never describe planned behavior as supported.
12. Run Ruff formatting and linting, strict mypy, and pytest before declaring work
    complete.

## Orientation and repository identity

- Use the installed, version-matched ProjectAtlas skill and MCP tools as the
  repository orientation layer before broad source reads.
- Run `projectatlas init` only when `.projectatlas` state is absent. After source
  changes, use the skill's incremental freshness workflow (`atlas_watch_once` or
  `projectatlas watch --once`) instead of an unconditional full scan.
- Project: NetSage, an open-source, provider-agnostic AI Network & Infrastructure
  Investigator.
- Repository: <https://github.com/Oexyz/NetSage>
- Default branch: `main`
- Python package and CLI command: `netsage`
- Current package version: `0.1.0.dev0`
- License: Apache License 2.0.
- Status: early development. The current repository is a tested foundation, not
  a production-ready network investigation product.

## Work completed so far

The initial project foundation was created, committed, and pushed to GitHub. The
work is represented by the following commits on `main`:

- `b3bdd38 chore: initialize NetSage project`
- `dde803b ci: stabilize Ruff import classification`
- `86e1620 fix: type Windows installer across platforms`
- `2f68784 fix: include credential isolation package`
- `5ea3585 fix: normalize Windows paths consistently`
- `57d6947 feat: establish core architecture`
- `d3f9fc6 feat: add FortiOS read-only driver`
- `5a57ce3 fix: support FortiOS performance memory totals`
- `88ae210 feat: add deterministic evidence investigations`
- `37e7619 feat: add secure FortiOS device onboarding`
- `322ad38 feat: add persistent investigation history`
- `2fd7d14 feat: add secure agent runtime boundary`
- `f5b74a9 feat: add Codex-first OpenAI runtime`
- `da355c1 feat: add FortiOS command catalog and interactive shell`
- `88044d9 test: make interactive help assertions portable`
- `ed9adfa feat: add safe FortiOS catalog execution`
- `5754b98 docs: add intermittent WAN failure case study`

The published baseline before the active native-OAuth milestone is `5754b98`,
with GitHub Actions run `32526437839` successful. The repository is
public; no release tag or GitHub Release has been created yet. Do not claim
downloadable release assets exist until a `v*` tag has successfully completed
the release workflow.

The current local verification snapshot is recorded in `CURRENT_MILESTONE.md`.
Do not copy historical test totals from this guide when newer live gate output is
available.

As of 2026-08-22, Ruff format/check and strict mypy pass for 101 source files,
pytest reports 286 passing tests with 86.50% coverage, the generated-catalog drift
check is clean, and all configured pre-commit hooks pass. Native ChatGPT/Codex
OAuth login, keyring storage, strict synthetic inference, refresh rotation, an
authorized FortiOS AI investigation, and the rebuilt/installed Windows standalone
were verified live without configuration changes or token leaks.

FortiOS Read-Only Catalog Execution Foundation is published on `main` and
CI-green at `ed9adfa`. The active milestone is Native Codex OAuth Provider.
Its implementation, tests, standalone, and authorized live verification are
complete locally; consult `CURRENT_MILESTONE.md`, Git, and current gate output
for publication state.
`fortios.md` is local copyrighted reference material and must remain ignored;
generated metadata, tests, and honest coverage documentation are the repository
artifacts.

### Development-machine bootstrap

The initial bootstrap was performed on Windows 11 Pro x64 with PowerShell 5.1.
The verified local toolset on 2026-08-19 was:

- Git 2.55.0.windows.4
- Python 3.13.15 for the project virtual environment
- uv 0.12.5 installed through WinGet
- OpenSSH for Windows 9.5p2
- Docker 29.7.2 and Docker Compose 5.4.0; both are optional for current work
- GitHub CLI 2.97.0, authenticated sufficiently to query and push this repository
- ProjectAtlas runtime/plugin 0.4.4 with project-local state under `.projectatlas`
- Node.js happens to be present on the bootstrap machine, but NetSage does not
  require Node.js or npm and agents must not add a frontend toolchain without a
  concrete project need.
- CMake and Visual C++ compiler commands were not required for the locked Python
  dependency set and were not added as project prerequisites.

The machine also has a newer global Python, but this project is intentionally
pinned to `>=3.13,<3.14`. Use uv and the project environment; do not rely on the
global `python` command selecting the correct interpreter. A newly installed
Windows command may require a fresh terminal before it appears on `PATH`.

### Python project and dependencies

- The project uses the `src/` layout, Hatchling as its build backend, uv for the
  interpreter, virtual environment, dependency resolution, and `uv.lock`.
- `requirements.txt` is not the primary dependency mechanism and should not be
  introduced for ordinary development.
- Runtime dependencies currently include Typer, Rich, Pydantic,
  pydantic-settings, HTTPX, AsyncSSH, cryptography, keyring, PyYAML, structlog,
  Scrapli, and the official OpenAI Python SDK.
- Scrapli was selected as the initial network transport library. Netmiko was not
  added because both are not yet needed. Re-evaluate only for a concrete driver
  requirement.
- FastAPI and Uvicorn were intentionally omitted because no backend service is
  implemented yet.
- Development dependencies include pytest, pytest-asyncio, pytest-cov, Ruff,
  mypy, pre-commit, types-PyYAML, and PyInstaller.
- The console entry point is `netsage = "netsage.cli.main:app"`.

### CLI foundation

The Typer/Rich CLI currently implements and tests:

- `netsage --help`
- `netsage --version`
- `netsage` as a NetSage-only interactive shell
- `netsage doctor`
- `netsage -install` as an alias for per-user Windows standalone installation
- `netsage install-path`
- `netsage uninstall-path`
- `netsage fortigate live-test` as an experimental, interactive, read-only
  process-memory-only connection test
- `netsage fortigate investigate` as an evidence-backed deterministic health
  investigation using the same secure connection flow
- `netsage setup`
- `netsage credentials add|list|show|remove`
- `netsage credentials rotate PROFILE`
- `netsage device add|show|test|remove|trust-reset`
- `netsage devices`
- `netsage investigate DEVICE`
- `netsage investigate DEVICE --ephemeral`
- `netsage investigations`
- `netsage investigation show|remove UUID`
- `netsage audit --limit N`
- `netsage fortios commands search|show|coverage`
- `netsage fortios run DEVICE COMMAND_ID [--arg NAME=VALUE] [--dry-run] [--json]`
- `netsage ai status`
- `netsage ai configure --provider ...`
- `netsage ai codex login|status|logout|import-existing`
- `netsage ai openai status|login|logout|models|configure`
- `netsage ask DEVICE "question"` for the visible selected-provider workflow

`doctor` reports Python, Git, SSH, OS credential-store, optional Docker, and safe
AI runtime/auth status. Local state, credential metadata, SSH trust, FortiOS
Device-ID, and AI workflows are functional but experimental.

The FortiGate driver and interactive live-test path are implemented,
fixture-verified, and live-verified against an authorized FortiOS 7.2.13 device.
The password was entered through the hidden local prompt and was not persisted.
NetSage cannot modify a network device.

The complete persistent workflow (`setup`, keyring credential, Device add/test,
and stored investigation) is also live-verified. Real connection metadata exists
only in the user's local state; no production values or raw captures belong in
the repository.

Persistent and ephemeral Investigation modes are live-verified. The local SQLite
database successfully reloads typed Reports/Evidence and append-only Audit across
processes; a byte scan found no credential material.

The current runtime selection prefers configured native `openai-codex` OAuth,
then an optional installed Codex App Server, then a separately configured
`openai-api` key. Native OAuth requires neither Codex nor Node.js. Tokens live
only in the provider-specific OS keyring; compatible Codex auth import requires
explicit confirmation and never modifies its source.

### Architecture contracts

The foundation has intentionally small, testable boundaries:

- `NetworkDriver` is an async, vendor-neutral, read-only abstract contract with
  `get_facts`, `get_interfaces`, `get_vlans`, `get_mac_table`, `get_arp_table`,
  `get_routes`, `get_lldp_neighbors`, `get_system_health`,
  `get_firewall_policies`, `ping`, and `traceroute`.
- `AIProvider` accepts only sanitized context and broker-owned `StructuredTool`
  definitions and returns typed provider-neutral final/tool-call responses.
  `CodexOAuthProvider` implements native experimental ChatGPT/Codex OAuth;
  `CodexProvider` implements the optional official installed App Server;
  `OpenAIProvider` implements the separate API-key path through the official
  Python SDK and Responses API. Claude, Ollama, and compatible providers do not
  exist yet.
- `CredentialProvider` resolves opaque credential references inside the trusted
  connection boundary. `Credential` uses `repr=False`, and its values must never
  cross into prompts, logs, evidence, or tool results.
- `KeyringCredentialProvider` combines non-secret profile metadata with a password
  retrieved under keyring service `NetSage`. It fails closed when the backend or
  secret is unavailable and has no plaintext fallback.
- `SSHAgentCredentialProvider` and `DevelopmentEnvironmentCredentialProvider`
  remain fail-closed stubs.
- `EphemeralCredentialProvider` retains one credential in process memory only
  for a bounded operation. It must never be backed by CLI arguments, environment
  variables, files, inventory serialization, logs, or audit events.
- `ToolBroker` registers typed definitions, rejects generic or duplicate tools,
  validates declared arguments, inventory devices, and capabilities, applies
  Observe authorization, redacts results and audit arguments, and checks handler
  result identity.
- `AuditEvent` is persisted by append-only `SQLiteAuditSink` for normal Device
  investigations; `InMemoryAuditSink` remains for tests and ephemeral mode.
- `DeviceRef` stores non-secret device metadata, capabilities, and an opaque
  `CredentialReference`; `CommandResult` marks sanitized output as untrusted
  device data.
- Inventory, site, and device-group models validate references. The default
  Observe policy denies configuration and destructive operations.
- `SecretRedactor` handles sensitive structured fields, common raw-output
  patterns, private keys, token forms, and explicitly known credential values.
- `FakeDriver` exposes only explicitly configured typed fixtures and raises for
  unsupported capabilities.
- The FortiOS package contains the first real read-only driver. Its fixed SSH
  allowlist supports facts, interfaces, VLANs, ARP, routes, health, IPv4 firewall
  policies, and policy-controlled IP-only ping/traceroute. Host-key pinning is
  mandatory, credentials resolve only inside the trusted transport, and paged
  output is advanced without changing the device's global console configuration.
- The generated FortiOS 7.2.13 knowledge catalog is separate from that transport
  allowlist. It records all source-derived definitions with policy, promotion,
  argument, and source metadata. The expert executor promotes 515 of 1,049
  READ_ONLY definitions to bounded `SANITIZED_TEXT`; 362 require review and 172
  are non-executable. Catalog-only entries never reach SSH.
- `FortiOSCatalogExecutor` accepts only Device/Command IDs and named values,
  checks generated disposition and ObservePolicy, validates/renders arguments,
  reuses the existing pinned runtime/transport, double-redacts and bounds output,
  returns untrusted non-persistent/non-Evidence results, and records secret-free
  Audit metadata. The transport repeats ID/class/disposition checks before
  credential resolution.
- FortiSwitch, HP/HPE/ArubaOS-Switch (`aruba_aoss`), and Aruba AOS-CX
  (`aruba_aoscx`) remain driver placeholders.
- `EvidenceEnvelope` retains typed normalized payloads, UTC timestamps, explicit
  untrusted-data marking, UUID references, and non-secret provenance. Evidence is
  created only from Broker results and stored in a secret-rejecting in-memory
  store; persistence remains future work.
- The deterministic investigation domain supports FortiOS health, active IPv4
  default-route, and interface-state workflows with findings, qualitative
  diagnoses, partial-evidence handling, and AI-independent reports. The complete
  health-investigation CLI was live-verified against an authorized FortiOS 7.2.13
  device without persisting credentials, evidence, or raw output.
- Topology and incidents remain scaffolding only. The bounded AgentRuntime and
  FortiOS-only AI `ask` composition are implemented; no autonomous device or
  local-shell agent exists.
- Local state uses four schema-versioned YAML documents for settings, Inventory,
  credential metadata, and SSH fingerprints. `history.sqlite3` separately stores
  typed sanitized Evidence/Reports and secret-free Audit with schema version 1,
  foreign keys, transactions, and restrictive user-level permissions.
- FortiOS onboarding verifies an unauthenticated discovered host key before
  keyring resolution/authentication, rejects changes, and persists a Device only
  after read-only facts succeed.
- `AIContextBuilder` exposes only logical device metadata, typed untrusted
  Evidence, deterministic findings, and missing Evidence. It fails closed when a
  configured SecretRedactor recognizes credential material.
- `AgentRuntime` has hard step/tool budgets, repeat protection, Broker-only tool
  execution, Evidence-only results, and final Evidence-reference validation.
  `FakeAIProvider` is deterministic and performs no external traffic.
- `CodexOAuthProvider` uses current device authorization and the isolated Codex
  backend, keeps one atomically activated token-bundle generation under keyring service
  `NetSage AI OpenAI Codex`, serializes refresh, follows no redirects, identifies
  itself as NetSage, and exposes no provider-owned tools. This is experimental
  compatibility, not a guaranteed third-party OAuth contract.
- `OpenAIProvider` uses the official Python SDK, its separate provider-specific
  OS-keyring API key, authenticated model listing, `store=false`, no built-in
  OpenAI tools, and Pydantic Structured Output. OAuth/API-key crossover is denied.
- `CodexProvider` uses the documented App Server, Codex-managed auth, ephemeral
  isolated threads, a scrubbed environment, disabled provider-owned tools, and
  strict Structured Output. Installed but unusable Codex fails closed rather
  than silently selecting potentially billable API usage.
- The interactive shell reuses the same Typer command tree as one-shot commands.
  It has no OS-shell fallback, persists no command history, and performs no
  device/AI network access at startup.

### Standalone distribution

- PyInstaller builds one native console executable using `netsage.spec` and
  `scripts/netsage_entry.py`.
- `scripts/package_binary.py` gives release assets their platform-specific names.
- `scripts/build-binary.ps1` and `scripts/build-binary.sh` provide local build
  entry points. PyInstaller does not cross-compile; build on the target OS and
  architecture.
- The Windows executable installs without administrator privileges into
  `%LOCALAPPDATA%\NetSage\bin\netsage.exe` and updates only the current user's
  `PATH`. It does not install a service or configure credentials.
- Windows path handling is normalized case-insensitively and avoids duplicate
  entries. Uninstall removes the user-level path entry; a currently running
  executable may need manual deletion after the process exits.
- Windows release binaries are not Authenticode-signed yet, so publisher warnings
  are expected and must be documented honestly.
- `install.sh` supports Linux x64 and ARM64, installs to `~/.local/bin` by default,
  requires HTTPS for normal downloads, verifies the selected asset against
  `SHA256SUMS`, and performs an atomic staged install.
- Linux installer overrides (`NETSAGE_VERSION`, `NETSAGE_INSTALL_DIR`,
  `NETSAGE_REPOSITORY`, and test-only/mirror `NETSAGE_DOWNLOAD_BASE`) are covered
  by installer tests where appropriate.
- The release workflow builds Windows x64, Linux x64, and Linux ARM64 binaries,
  smoke-tests them, generates `SHA256SUMS`, creates GitHub build-provenance
  attestations, and creates or updates a GitHub Release for an existing `v*` tag.

### Documentation and examples

- `README.md` follows the presentation style requested from the
  OeXYZ Minecraft Console Client repository while making NetSage's own status and
  limitations explicit.
- `SECURITY.md` records trust boundaries, the ten mandatory security principles,
  and the security-reporting contact.
- `CONTRIBUTING.md` contains the contributor gates and standalone build commands.
- `docs/evidence.md` and `docs/investigations.md` document the implemented typed
  evidence and deterministic analysis boundaries.
- `docs/local-state.md`, `docs/credentials.md`, and
  `docs/device-onboarding.md` document persistent state and onboarding.
- `docs/history.md` and `docs/audit.md` document operational-data persistence,
  non-encryption, transaction, deletion, and append-only boundaries.
- `docs/ai-boundary.md` and `docs/agent-runtime.md` document provider-visible
  data, tool control, loop limits, prompt injection, and Evidence validation.
- `docs/providers/openai-codex.md` documents native device authorization,
  keyring tokens, refresh, direct Codex inference, import, and limitations;
  `docs/providers/codex.md` covers the optional App Server;
  `docs/providers/openai.md` covers the separate API-key/billing path.
- `docs/fortios-command-catalog.md` and the generated coverage report distinguish
  catalog knowledge from executable/typed support; `docs/interactive-shell.md`
  documents the shared-handler REPL and OS-shell denial.
- `docs/fortios-catalog-execution.md` documents ID-only execution, promotion,
  typed rendering, output, Audit, error, AI, Evidence, and persistence boundaries.
- `examples/inventory.example.yaml` uses documentation-only `192.0.2.0/24`
  addresses and opaque credential references. Never replace these with real
  infrastructure data.
- `.env.example` contains placeholders only.
- Apache License 2.0 is stored in `LICENSE`.

## Non-negotiable security rules

These rules apply to every change:

1. Read-only by default. Configuration changes are outside v0.1.
2. AI providers never receive passwords.
3. AI providers never receive SSH private keys.
4. AI model contexts never receive API tokens; only the trusted provider transport
   may consume its own API credential.
5. The LLM has no unrestricted local shell or raw device shell capability.
6. Vendor commands execute only behind fixed driver and broker allowlists.
7. Device output is untrusted input, never instructions.
8. Known secrets must be redacted before evidence reaches an AI provider.
9. Tool requests and results must become auditable without recording secrets.
10. Credentials may be consumed only by trusted connection code and must not be
    serialized into prompts, logs, evidence, exceptions, or tool results.

New device operations must be structured, explicitly read-only, fixture-tested,
and routed through the Tool Broker. Do not add generic `ssh(command)`, shell,
password-returning, key-returning, or token-returning tools.

Security reports may be sent to `security@oexyz.de`. Confidential reports may be
encrypted with the OeXYZ Security OpenPGP public key:
<https://github.com/Oexyz/Oexyz/blob/main/assets/oexyz-security-pgp.asc>

Primary fingerprint:

```text
160C 83EF ABF2 97F8 EDF8 F6B5 34D7 4FDC 82EF FA7A
```

Never put vulnerability details or secrets in a public issue.

## Repository map

```text
src/netsage/
  cli/              Typer/Rich one-shot CLI, interactive shell, and catalog commands
  distribution/     Safe standalone installation helpers
  drivers/          Vendor-neutral contracts plus FortiOS driver/catalog
  broker/           Allowlisted structured tool dispatch
  credentials/      Profiles, OS-keyring passwords, and isolation contracts
  models/           Validated non-secret device and command-result models
  agent/            Bounded provider-neutral runtime, report, and FortiOS AI composition
  ai/               Typed context/tools/responses plus native OAuth, App Server, and API providers
  evidence/         Typed Broker-result evidence, provenance, and store contract
  history/          SQLite lifecycle, typed Evidence/Report stores, and Audit sink
  investigations/   Deterministic evidence-backed workflows and reports
  inventory/        Validated Inventory and atomic YAML persistence
  onboarding/       FortiOS Device-ID runtime, readiness, and CRUD workflows
  state/            Platform paths, atomic YAML, settings, and SSH trust
  topology/         Future topology models
  incidents/        Future incident workflows
  policies/         Future authorization/read-only policies
  security/         Future reusable security controls
  tools/            Structured Broker adapters; currently FortiOS
tests/unit/          CLI, contracts, broker, and Windows distribution tests
tests/install/       Linux installer shell test
tests/integration/   Reserved for later integration tests
tests/fixtures/      Vendor-specific sanitized fixtures; currently placeholders
examples/            Safe example configuration
scripts/             Native executable build and packaging helpers
.github/workflows/   CI and tagged-release workflows
```

## Development workflow

Use uv for all Python environment and dependency operations:

```powershell
uv sync --locked --dev
uv run netsage --help
uv run netsage --version
uv run netsage doctor
```

Run every quality gate before considering a code change complete:

```powershell
uv run ruff format .
uv run ruff check .
uv run mypy src
uv run pytest
```

CI uses the non-mutating formatter check:

```powershell
uv run ruff format --check .
```

Pytest enforces at least 80% coverage through `pyproject.toml`. The GitHub Actions
CI workflow runs locked dependency installation, Ruff formatting, Ruff lint,
strict mypy, pytest, `bash -n install.sh`, and the Linux installer test.

For standalone binaries:

```powershell
.\scripts\build-binary.ps1
```

```bash
sh scripts/build-binary.sh
```

Use pre-commit when available. Its configured hooks run Ruff, YAML validation,
end-of-file and trailing-whitespace fixes, and private-key detection.

## Git and secret hygiene

- Preserve unrelated user changes in a dirty worktree.
- Do not commit `.env`, private keys, PEM files, credential files, secret files,
  virtual environments, caches, coverage output, build output, or artifacts.
- `.gitignore` intentionally keeps `.env.example` while excluding real `.env*`
  files and ignores `.projectatlas` local state.
- Never add real device captures. Sanitized fixtures must be synthetic or stripped
  of hostnames, usernames, IPs, serial numbers, tokens, keys, and customer data.
- Do not invent Git user identity. The initial repository already has commits, but
  future agents must still respect the active environment's configured identity.
- Do not create tags, releases, deployments, or external messages unless the user
  explicitly asks for that external state change.

## Deliberately out of scope now

Do not imply that the following exist, and do not add them incidentally:

- automatic or production network configuration changes
- functional FortiGate or switch configuration workflows
- unrestricted SSH or shell access for an AI model
- Claude, Ollama, Gemini, OpenRouter, or another provider
- a web dashboard or local API service
- an MCP server
- automatic discovery
- Cisco, Arista, or Juniper drivers
- database clusters, Kubernetes, or enterprise authentication

## Next recommended milestone

Complete Native Codex OAuth Provider before beginning anything else. After it is
verified, return to a small reviewed set of semantic FortiOS operations or
broaden deterministic investigations. Do not automatically begin another
provider, vendor, discovery, topology, probe, vantage-point, MCP, Web, or
configuration milestone.
