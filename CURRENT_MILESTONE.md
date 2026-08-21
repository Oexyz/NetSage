# Current Milestone: FortiOS CLI Coverage & Interactive Shell

Status: complete. Source-derived command coverage, the shared-handler interactive
shell, security tests, documentation, authorized read-only live verification,
standalone installation, and every repository quality gate are proven green.
Keep all work local and do not push.

## Goals

- treat `fortios.md` as the authoritative FortiOS 7.2.13 CLI command source;
- scan the complete source deterministically and generate a versioned runtime
  manifest rather than parsing the 7 MB reference at application startup;
- catalogue every unique documented configuration, diagnose, and execute command
  path, including documented configuration-context subcommands;
- retain source line/page traceability, command context, typed arguments where
  practical, capability mapping, execution support, and parser support;
- classify every definition as read-only, diagnostic, configuration, or
  destructive using command semantics and conservative fail-closed rules;
- distinguish `known`, `executable`, and `typed output` without claiming that
  catalog coverage equals full device support;
- keep configuration/destructive commands denied in Observe mode and diagnostics
  subject to explicit policy;
- preserve the closed FortiOS transport allowlist; do not add a generic raw CLI
  execution surface;
- add local `fortios commands search|show|coverage` inspection commands which
  never connect to a device;
- start a NetSage-only interactive shell when `netsage` has no flags or
  subcommand, while preserving every existing one-shot Typer command;
- route shell commands through the same Typer application/handlers, with safe
  tokenization and no OS command fallback;
- cover help, nested commands, quoting, exit/quit, EOF, Ctrl+C, handler
  equivalence, and OS-shell rejection in tests;
- document exact generated coverage counts and honest parser/execution limits.

## Non-goals

- no configuration or destructive execution;
- no Plan/Apply mode, remediation, or change engine;
- no generic `run_command`, SSH, shell, or unvalidated CLI-string tool;
- no automatic exposure of the complete catalog to AI context;
- no persistence of unsanitized raw CLI output;
- no additional vendors, Discovery, Topology, probes, vantage points, Web UI,
  FastAPI, MCP server, or additional AI providers;
- no autocomplete dependency unless it remains small, optional, and clearly
  justified after the required scope is complete.

## Security invariants

- `AI -> Structured Tools -> AgentRuntime -> ToolBroker -> ObservePolicy ->
  FortiOS Driver` remains the only AI-to-device path;
- the generated catalog is knowledge and policy metadata, not an execution
  bypass;
- command strings executable by a driver remain composed only from reviewed
  definitions and validated typed arguments;
- Observe allows read-only operations, allows diagnostics only by explicit name,
  and denies configuration/destructive classes;
- device credentials remain exclusively inside trusted connection code;
- device data remains untrusted and must be redacted before any text result can
  cross an AI, Evidence, Audit, logging, or persistence boundary;
- the interactive shell executes only registered NetSage commands and never
  invokes `os.system`, `shell=True`, a system shell, or unknown executables;
- credential/API-key values remain hidden prompts and never become shell history
  or command-line arguments.

## Completion evidence required

- generator reads all bytes/lines of `fortios.md`, records its SHA-256, and emits
  a deterministic manifest clearly marked generated/do-not-edit;
- regeneration produces no diff and a drift test compares the source extractor
  directly with the committed manifest;
- documented command count equals catalogued unique definition count with zero
  uncatalogued source definitions and zero duplicate IDs;
- every definition has valid class, capability/context metadata, source line/page,
  and a valid execution/parser support state;
- configuration/destructive policy-denial and typed rendering/injection tests;
- all required interactive shell and one-shot equivalence/security tests;
- README, AGENTS, SECURITY, drivers documentation, command-catalog documentation,
  and interactive-shell documentation match actual behavior;
- authorized live verification executes only existing read-only/explicitly
  allowed diagnostic operations; no configuration/destructive command is tested;
- Ruff format/check, strict mypy, full pytest coverage, and pre-commit pass;
- rebuilt standalone opens the shell with no arguments and preserves one-shot
  commands;
- no credential, token, private key, real device capture, or infrastructure
  identifier is added to the repository;
- no commit, push, tag, release, or external publication.

## Known source facts established before implementation

- `fortios.md` is the FortiOS 7.2.13 CLI Reference converted from PDF;
- source size is 7,055,249 bytes and 135,987 logical lines under Python's
  `splitlines()` handling;
- authoritative content sections begin with CLI configuration commands,
  CLI diagnose commands, and CLI execute commands;
- the conversion has no separate `get` or `show` reference sections; existing
  fixed driver `get/show` operations remain outside source-derived coverage;
- the conversion uses plain text and Markdown tables rather than headings or
  fenced code blocks, so extraction must normalize wrapped/misaligned table cells;
- all 4,972 unique topic-list paths (564 configuration, 3,785 diagnose, 623
  execute) map to extracted syntax paths without omission;
- source tables contain 232 additional complete diagnose/execute syntax paths
  which are absent from those topic lists and are catalogued independently;
- 55 remaining command-like rows are explicitly proven to be truncated
  conversion or prose artifacts rather than uncatalogued commands;
- configuration grammar extraction adds 13,826 scoped definitions, producing
  19,030 unique catalog entries in total;
- the source file is copyrighted vendor reference material and remains ignored;
  the repository contains only deterministic generated metadata, source hash,
  tests, and coverage documentation.

## Verification completed

- deterministic generation and immediate `--check` regeneration are clean;
- focused catalog, classification, policy, rendering, CLI, shell, quoting,
  equivalence, EOF/Ctrl+C, and OS-execution-denial tests pass;
- 220 tests pass with 87.59% total coverage;
- Ruff format/check and strict mypy pass for 91 source files;
- the generator drift check and every configured pre-commit hook pass;
- the authorized stored FortiOS device passed the existing read-only readiness
  test and an ephemeral deterministic investigation;
- live output confirmed the no-configuration-change statement and disabled
  History persistence; no raw operational output was retained in the repository;
- wheel inspection confirms that the generated compressed manifest is packaged;
- the rebuilt Windows standalone includes all 19,030 definitions, reports zero
  uncatalogued source definitions, opens the interactive shell with no arguments,
  preserves one-shot commands, rejects an OS command, and is installed in the
  user-level NetSage path.

## Next recommended milestone

Only after this milestone is fully complete: persist validated final AI
assessments or broaden deterministic FortiOS investigations. Do not start another
vendor, provider, or configuration workflow.
