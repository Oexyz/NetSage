# Current Milestone: FortiOS Semantic Compatibility Hardening & Supported Readiness

Status: complete. Publication is valid only when the corresponding compatibility
commit is present on `main` and GitHub CI is green.

## Published baseline

- `f17b9e4 feat: expand FortiOS semantic observability` is published on `main`;
- GitHub Actions run `32566925327` is successful;
- `fortios.md` and the original vendor PDF remain local, ignored, and
  unpublished.

## Goal

Make the existing FortiOS semantic surface robust across observable firmware,
model, feature, VDOM, permission, command-availability, and output-shape
differences. The milestone adds compatibility characterization, not more vendors,
AI providers, arbitrary commands, diagnostics, or configuration behavior.

## Planned delivery

- typed FortiOS firmware and compatibility-state models;
- explicit enabled, disabled, not-configured, unavailable, permission-denied,
  unrecognized, and partial states;
- a maximum of two or three reviewed version-aware command variants per semantic
  operation where a fallback is evidence-backed;
- fallback only for command-unavailable or output-variant failures;
- VDOM mode/context characterization without generic context changes;
- a sequential, bounded `netsage fortios compatibility DEVICE` probe;
- machine-readable JSON and atomic safe-by-default anonymized export;
- parser provenance, variant matrices, privacy/security canaries, and
  representative live verification.

## Core compatibility areas

- System facts and health;
- Interfaces;
- Routing;
- Firewall policies;
- HA;
- SD-WAN;
- IPsec;
- BGP;
- OSPF.

## Security decisions

- compatibility uses existing semantic Broker tools and trusted runtime only;
- no raw CLI, Credential, management address, peer address, route, neighbor,
  interface address, serial number, hostname, or provider credential enters the
  report/export;
- exported reports are anonymized by default and contain only normalized model
  family, typed firmware, VDOM category, parser/variant metadata, and capability
  states;
- no arbitrary fallback, AI-selected command, privilege escalation, context
  configuration, or feature activation;
- the AI tool surface remains the existing five comprehensive semantic tools;
- catalog totals and the 515-command expert subset remain unchanged.

## Non-goals

- no FortiSwitch, Aruba, HPE, Cisco, Arista, Juniper, MikroTik, Palo Alto, or
  other real driver;
- no OAuth/provider refactor and no new AI provider;
- no Discovery, scanning, Topology, Vantage Point, Probe, MCP, Web, Plan, Apply,
  or remediation work;
- no feature configuration for live tests;
- no automatic FortiOS Supported promotion.

## Completion evidence required

- strongly typed report, variants, errors, firmware and capability states;
- parser and compatibility matrix tests for every named domain and failure path;
- JSON/export/REPL equivalence and privacy canaries;
- existing History/Evidence and AI tool surface remain compatible;
- authorized `device test` and compatibility probe run without configuration;
- complete Ruff, strict mypy, pytest/coverage, pre-commit, catalog drift,
  Markdown, secret/vendor-source, Git, push, and GitHub-CI verification;
- objective `READY FOR SUPPORTED` or `KEEP BETA` decision backed by the resulting
  compatibility matrix.

## Implementation delivered

- `FortiOSVersion` with numeric range matching and optional build, branch point,
  and release metadata;
- explicit capability, parser, feature, error, VDOM-mode, and VDOM-context
  states;
- permission-denied, command-unavailable, and generic rejection transport
  categories;
- two reviewed, version-bounded variants each for BGP and OSPF with controlled
  fallback only;
- hardened System, Interface, Routing, Firewall, HA, SD-WAN, IPsec, BGP, and
  OSPF parser variants;
- parser schema/variant/state Evidence provenance with legacy loading defaults;
- sequential ten-operation Broker-only compatibility probe;
- typed report schema, reproduction fingerprint, anonymized JSON, atomic export,
  overwrite confirmation, and symlink refusal;
- one-shot and REPL `fortios compatibility` command;
- `docs/fortios-compatibility.md` test/live/Supported-readiness matrices.

## Verification completed

- 376 tests pass with 87.15% coverage;
- Ruff format/check and strict mypy pass for 118 source files;
- generated FortiOS catalog remains current at 19,030 definitions and 515 safe
  expert executions;
- 27 Markdown files have no broken internal links, fences, or tables;
- authorized `device test` succeeds;
- authorized anonymized compatibility report succeeds on FortiOS 7.2.13 in
  single-VDOM/root context;
- live states: System/Interfaces/Routing/Firewall Supported, HA/OSPF Enabled and
  Parsed, SD-WAN Disabled and Parsed, IPsec Enabled and Partial, BGP Output
  Unrecognized after both reviewed variants;
- no feature was configured and no raw output was persisted;
- final pre-commit, secret/vendor-source, Git, push, and CI evidence are recorded
  by the completion report rather than assumed here.

## Supported-readiness decision

**KEEP BETA.** The compatibility architecture is robust and reproducible, but
live BGP remains unrecognized, IPsec remains Partial, and active SD-WAN,
OSPF-adjacency, multi-VDOM, restricted-permission, additional model, and
additional firmware reports remain unavailable.
