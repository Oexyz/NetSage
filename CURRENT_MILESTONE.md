# Current Milestone: Native Codex OAuth Provider

Status: complete. Native device authorization, keyring persistence, refresh,
structured inference, provider selection, CLI/REPL integration, clean-machine
simulation, standalone distribution, security checks, and authorized live
verification are complete.

## Published baseline

- `ed9adfa feat: add safe FortiOS catalog execution` is published and CI-green;
- `5754b98 docs: add intermittent WAN failure case study` is published and
  CI-green;
- `main` and `origin/main` are synchronized at `5754b98` before this milestone;
- `fortios.md` and the original vendor PDF remain local, ignored, and unpublished.

## Goal

Provide an experimental `openai-codex` AIProvider that authenticates directly
through the currently compatible ChatGPT/Codex device-authorization flow. A
fresh machine must be able to run `netsage ai codex login` without a Codex
executable, Node.js, `~/.codex`, or an OpenAI API key.

## Implemented scope

- isolate current compatibility endpoints and public client identifier in one
  protocol module with reference commit provenance;
- use the current Codex device-code flow, authorization-code exchange, refresh
  endpoint, account-ID claim, and dedicated Codex Responses backend;
- store access, refresh, and ID tokens as one atomically activated, size-safe
  generation under the separate `NetSage AI OpenAI Codex` OS-keyring service;
- keep provider authentication distinct from FortiGate credentials and the
  separate `openai-api` keyring service;
- serialize in-process refreshes with an async lock and replace the complete
  token bundle only after a valid refresh response;
- expose `ai codex login|status|logout|import-existing` through the same Typer
  handlers in one-shot CLI and REPL;
- require explicit confirmation before reading a compatible Codex `auth.json`;
  never modify or delete that source;
- retain the installed Codex App Server as an optional, explicitly named
  `codex-app-server` route;
- support visible `auto`, `openai-codex`, `codex-app-server`, and `openai-api`
  selection without token crossover;
- map strict structured Codex output into the existing provider-neutral
  responses and keep AgentRuntime/ToolBroker authoritative;
- send no provider-owned tools and retain `store=false`, bounded timeouts,
  bounded SSE output, safe errors, TLS verification, and no redirects.

## Security invariants

- Codex OAuth tokens never enter YAML, SQLite, History, Evidence, Audit, reports,
  logs, CLI output, AIContext, or exceptions;
- there is no token reveal/export command and no environment/plaintext fallback;
- OAuth tokens are used only with the compatible Codex backend, never
  `api.openai.com/v1/responses`;
- the OpenAI API provider uses only its own API key and usage-based billing;
- the model sees exactly the same sanitized AIContext and Broker-owned tool
  metadata as every other provider;
- no Codex shell, filesystem, MCP, web, browser, computer use, or autonomous tool
  execution is exposed;
- no network-device credential, host address, SSH trust, CredentialReference,
  raw CLI, or internal persistence path crosses the AI boundary;
- configuration changes and every new hardware/vendor area remain out of scope.

## Compatibility status

OpenAI documents ChatGPT sign-in and device-code authentication for Codex
clients. The direct third-party backend protocol is not documented as a stable
general-purpose OAuth API. NetSage therefore labels this implementation an
experimental compatibility provider and keeps all change-prone values isolated.

Reference review performed on 2026-08-22:

- OpenAI Codex repository commit `4f39251a010a8bd7d692d25fb33832ff06f1635a`;
- NousResearch Hermes Agent commit `9ddb6547a062a81510a943cc54f525c25cf63d8f`;
- official OpenAI Codex authentication documentation.

## Non-goals

- no official-support guarantee for third-party Codex OAuth;
- no browser-cookie or browser-token extraction;
- no automatic Codex installation or dependency on Codex CLI;
- no automatic reading/importing of existing Codex credentials;
- no API-key/OAuth crossover or invisible paid fallback;
- no additional AI provider, vendor driver, FortiOS parser work, discovery,
  topology, vantage point, probe, MCP, Web UI, or configuration engine.

## Completion evidence required

- login success, authorization pending, slow-down, expiry, denial, malformed
  response, refresh success/failure, expired access, logout, and cancellation;
- existing-Codex source absent/valid/malformed/declined/imported and unchanged;
- clean-machine login initiation with no Codex executable, `.codex`, or API key;
- canaries absent from state, SQLite, Evidence, Audit, reports, AIContext, logs,
  exceptions, and terminal output;
- deterministic non-AI commands remain functional without OAuth;
- synthetic structured inference and full AgentRuntime integration pass;
- full Ruff format/check, strict mypy, pytest with coverage, pre-commit, and
  standalone build/install checks pass;
- authorized live ChatGPT/Codex login and synthetic inference are attempted and
  reported honestly; FortiOS AI investigation is performed only if safe and
  practical without exposing infrastructure data.

## Verification completed

- 286 tests pass with 86.50% total coverage; the configured floor remains 80%;
- Ruff format/check, strict mypy for 101 source files, and every pre-commit hook
  pass;
- device login success, pending, slow-down, expiry, denial, cancellation,
  malformed responses, access expiry, refresh success/failure, logout, and safe
  errors are tested without live accounts in CI;
- valid/absent/malformed/declined existing-Codex import paths are tested; import
  never modifies its source and writes no plaintext NetSage state;
- OAuth, API-key, and network-password canaries are absent from AIContext,
  provider input, Evidence, reports, Audit, SQLite, YAML, logs, exceptions, and
  CLI output; the opaque CredentialReference remains only expected Inventory
  metadata and is absent from provider/operational outputs;
- the Windows keyring store passed a real oversized synthetic-bundle roundtrip;
  generation chunks are written before the active pointer and partial writes
  roll back without replacing the prior generation;
- wheel and Windows standalone include every native-OAuth module; the standalone
  starts with a minimal system PATH where Codex, Node/npm, `.codex`, and
  `OPENAI_API_KEY` are absent;
- the final standalone is installed successfully for the current user and its
  native OAuth status command passes;
- authorized live ChatGPT device login, secret-free status, a synthetic strict
  Structured Output turn, forced refresh rotation, and a complete read-only
  FortiOS AI investigation all pass through `openai-codex`;
- live refresh rotated the access token, retained a refresh token, preserved
  account binding, and produced a future expiration;
- live repository/state/status-output scans found zero access-, refresh-, or
  ID-token occurrences; no state log file exists;
- the live FortiOS AI investigation returned a validated assessment, recorded
  the native provider ID, reported no provider error, and made no configuration
  change;
- no additional vendor, provider, discovery, topology, probe, or configuration
  functionality was introduced.

## Next recommended milestone

Only after this milestone is complete: return to reviewed semantic FortiOS
operations or deterministic investigations. Do not begin another provider or
vendor automatically.
