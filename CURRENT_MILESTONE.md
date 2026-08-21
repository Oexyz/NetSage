# Current Milestone: FortiOS Read-Only Catalog Execution Foundation

Status: complete. Every READ_ONLY definition has a source-derived execution
disposition; the safe subset uses only typed IDs/arguments and the existing
transport/policy boundary; required tests, representative live reads,
wheel/standalone, installation, and local gates are green. Publication is valid
only when the corresponding commit is present on `main` and GitHub CI is green.

## Published baseline

- `f5b74a9 feat: add Codex-first OpenAI runtime`;
- `da355c1 feat: add FortiOS command catalog and interactive shell`;
- `88044d9 test: make interactive help assertions portable`;
- `main` and `origin/main` are synchronized at `88044d9`;
- GitHub Actions run `32521802318` completed successfully;
- `fortios.md` and the original vendor PDF remain local, ignored, and
  unpublished.

## Catalog baseline

- total catalogued: 19,030;
- source coverage: 100%, uncatalogued: 0;
- read-only: 1,049;
- read-only safely executable: 515;
- read-only requires review: 362;
- read-only non-executable: 172;
- diagnostic: 2,758;
- configuration: 14,390;
- destructive: 833;
- currently structured executable: reviewed ping and traceroute only;
- the complete catalog remains excluded from AI tool exposure.

These totals are generator-derived rather than target values. Promotion excludes
side-effect terms, interactive/debug/streaming paths, sensitive paths/arguments,
tree parents, incomplete/ambiguous syntax, broad strings, and enum/boolean mode
arguments.

## Goals

- assign every READ_ONLY definition one explicit execution disposition:
  executable, requires review, or non-executable from available syntax;
- derive promotion metadata deterministically from the generator, with a concise
  classification/rejection reason and stable mass-validation totals;
- promote only complete, one-line, non-interactive, non-contextual, non-sensitive,
  unambiguous definitions with fully typed required/optional arguments;
- execute only by trusted catalog ID plus validated named arguments;
- introduce `FortiOSCatalogExecutor` as a separate expert layer responsible for
  lookup, disposition, authorization, rendering, bounded transport invocation,
  redaction, bounded untrusted result, and audit metadata;
- reuse the existing host-key trust, CredentialProvider, AsyncSSH transport,
  paging, timeout, and output-size boundaries; create no second SSH stack;
- retain the existing semantic operations for Investigations, Evidence, and AI;
- expose no catalog command automatically as an AI tool or Evidence source;
- add `netsage fortios run DEVICE COMMAND_ID` for the safe READ_ONLY subset in
  both one-shot CLI and the existing REPL;
- support local dry-run/render and optional secret-free JSON output;
- extend command info and coverage with exact execution-disposition/output totals;
- audit executions using stable `fortios_catalog:<command_id>` names without raw
  CLI or raw output.

## Non-goals

- no arbitrary command text, raw CLI, shell, command string, or expert bypass;
- no configuration or destructive execution;
- no newly auto-approved diagnostics; ping/traceroute retain their existing
  explicitly controlled semantic path;
- no multi-line or configuration-context sessions;
- no interactive/debug-stream/sniffer commands;
- no automatic Catalog Result persistence or Evidence creation;
- no AI promotion or Investigation Engine migration;
- no additional provider, vendor, hardware platform, discovery, topology,
  vantage point, probe, Web UI, MCP server, Plan/Apply mode, or remediation.

## Security invariants

- public execution input is `device_id + command_id + validated named arguments`,
  never a complete FortiOS string;
- READ_ONLY classification alone never implies execution eligibility;
- DIAGNOSTIC is denied unless an already reviewed semantic operation explicitly
  allows it; CONFIGURATION and DESTRUCTIVE are always denied;
- sensitive arguments and incomplete/ambiguous placeholders fail closed;
- renderer tokens come only from a trusted definition and validated values;
- command separators, newlines, substitutions, backticks, pipes, ampersands, and
  control characters are rejected;
- CatalogExecutor receives no username, password, Credential, keyring, or direct
  auth API; credentials resolve only inside the reused transport;
- results remain `UNTRUSTED_DEVICE_DATA`, are redacted, output-bounded, terminal
  only by default, absent from Evidence/History/AI, and never logged raw;
- every attempted execution receives a bounded category: `UNKNOWN_COMMAND`,
  `NOT_EXECUTABLE`, `POLICY_DENIED`, `INVALID_ARGUMENT`, `RENDER_FAILED`,
  `TRANSPORT_FAILED`, `OUTPUT_REDACTION_FAILED`, `OUTPUT_LIMIT_EXCEEDED`, or
  `INTERACTIVE_UNSUPPORTED`, `TIMEOUT`, or `AUDIT_FAILED`;
- no public API named `run_cli`, `execute_command`, `send_command`, or `raw_cli`.

## Completion evidence required

- deterministic manifest regeneration and source drift remain clean;
- mass validation covers all 19,030 definitions and all 1,049 READ_ONLY entries;
- exact executable/review/non-executable READ_ONLY totals are documented without
  a target invented in advance;
- no configuration/destructive definition is executable;
- no diagnostic is newly promoted;
- sensitive, context, interactive, streaming, incomplete, ambiguous, and
  malformed definitions are not executable;
- required/optional typed argument validation and injection tests;
- timeout, output limit, redaction, safe error, audit, dry-run, JSON, REPL,
  one-shot equivalence, no-AI-exposure, and no-persistence tests;
- representative authorized live reads for system, interface, routing, and
  firewall areas only; no mass execution and no state-changing command;
- README, AGENTS, SECURITY, command catalog, interactive shell, drivers, and
  execution documentation match actual behavior;
- Ruff format/check, strict mypy, full pytest, pre-commit, wheel/standalone,
  installation, secret/vendor-source checks, commit, push, and GitHub CI pass.

## Verification completed

- all 19,030 definitions and all 1,049 READ_ONLY entries pass mass validation;
- generated disposition totals are 515 executable, 362 requires-review, and 172
  non-executable; sensitive/interactive/contextual/incomplete/ambiguous/broad or
  side-effect-risk definitions are not promoted;
- diagnostics remain default-denied through Catalog Execution; configuration and
  destructive executable totals are zero;
- required/optional arguments, IP/integer/port/MAC/identifier rendering,
  injections, unknown/denied/interactive IDs, timeout, transport failure, output
  limit, redaction, terminal controls, audit failure, dry-run, JSON, Audit,
  no-persistence, no-Evidence, no-AI, REPL, and one-shot equivalence are tested;
- 260 tests pass locally with 88.07% total coverage;
- CI-equivalent execution without local `fortios.md` passes 258 tests with one
  intentional source-drift skip and 81.90% coverage;
- Ruff format/check and strict mypy pass for 93 source files;
- generator drift and every configured pre-commit hook pass;
- authorized live Catalog reads succeeded for system/HA, interface, routing, and
  firewall areas; two model-unavailable candidates failed safely and bounded;
- live Audit contains only stable IDs/safe metadata: four successes, two safe
  failures, no output, and no credential/configuration exposure;
- wheel and Windows standalone contain the execution layer and manifest;
- standalone/installed REPL, one-shot, dry-run, JSON, live read, raw-command
  rejection, untrusted output, no Evidence, and no persistence are verified;
- no mass live execution, diagnostic Catalog execution, configuration,
  destructive operation, AI promotion, or raw-output persistence occurred.

## Next recommended milestone

Only after this milestone is complete: promote a small reviewed set of catalog
commands to semantic normalized operations, or broaden deterministic FortiOS
investigations. Do not begin configuration execution or another vendor/provider.
