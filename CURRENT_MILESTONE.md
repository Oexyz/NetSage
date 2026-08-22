# Current Milestone: FortiOS Semantic Observability & Evidence Expansion

Status: complete. Publication is valid only when the corresponding FortiOS
feature commit is present on `main` and GitHub CI is green.

## Published baseline

- `ee128e9 feat: add native Codex OAuth provider` is published separately;
- `f81328d docs: classify NetSage alpha feature maturity` is published and
  CI-green;
- `fortios.md` and the original vendor PDF remain local, ignored, and
  unpublished.

## Goal

Turn selected high-value FortiOS read-only observations into vendor-neutral,
typed semantic data which can become bounded Evidence, deterministic findings,
and explicitly reviewed AI tools.

Priority domains are:

- HA;
- SD-WAN;
- IPsec;
- BGP;
- OSPF;
- focused improvements to routes, interfaces, system health, and firewall
  policy normalization where the available output is reliable.

## Architectural decisions

- semantic operations use fixed reviewed requests or trusted catalog IDs, never
  caller-supplied command strings;
- the existing host-key, credential, transport, timeout, paging, redaction,
  Broker, Evidence, History, and Audit boundaries remain authoritative;
- parsed device data remains `UNTRUSTED_DEVICE_DATA`;
- collections are explicitly bounded and report truncation;
- feature/model/firmware differences produce controlled missing Evidence rather
  than fabricated empty support;
- deterministic findings describe observed state and do not invent causes or
  numerical confidence;
- the 19,030-entry catalog and 515-command expert-execution subset remain a
  separate regression surface and are not exposed wholesale to AI.

## Planned semantic operations

- comprehensive status: HA, SD-WAN, IPsec, BGP, and OSPF;
- focused views: HA members, SD-WAN members and health checks, IPsec tunnels,
  BGP and OSPF neighbors, and a normalized route summary;
- deterministic investigations: HA health, SD-WAN health, IPsec health, and
  dynamic-routing health;
- AI visibility only for a small reviewed semantic subset.

The exact operation count may change when source or live evidence shows that an
operation cannot be implemented reliably. Quality and honest missing Evidence
take precedence over an artificial target count.

## Non-goals

- no new vendor or hardware integration;
- no new AI provider;
- no raw or arbitrary CLI;
- no configuration, destructive, or automatic-remediation surface;
- no broad diagnostic promotion;
- no bulk session dump or unbounded output;
- no FortiOS Supported label promotion by documentation alone.

## Completion evidence required

- typed models, parsers, Driver methods, capabilities, Broker tools, Evidence,
  deterministic findings, persistence roundtrips, AI boundary tests, and safe
  missing-Evidence behavior for implemented domains;
- anonymized fixtures including variants, malformed/empty/unsupported output,
  prompt-injection strings, and secret canaries;
- unchanged catalog totals and safe-execution regression;
- representative read-only live verification without configuring absent
  features;
- updated semantic coverage and Supported-readiness documentation;
- Ruff format/check, strict mypy, pytest/coverage, pre-commit, secret/vendor
  source checks, separate commit, push, and green GitHub CI.

## FortiOS maturity

FortiOS remains Beta. The objective recommendation is **KEEP BETA** because
active SD-WAN, BGP-neighbor, OSPF-adjacency, broader IPsec, additional HA, and
multi-model/firmware live matrices remain incomplete.

## Implementation delivered

- 12 semantic operations: HA status/members; SD-WAN status/members/health
  checks; IPsec status/tunnels; BGP status/neighbors; OSPF status/neighbors; and
  route summary;
- vendor-neutral bounded models and five comprehensive typed Evidence domains;
- optional interface counters/errors/duplex/role/parent, system session/conserve
  state, route active state, and firewall log-traffic normalization;
- fixed source-traceable semantic Catalog-ID requests for SD-WAN health, IKE
  gateway, and IPsec tunnel state without changing expert Catalog promotion;
- four feature-aware deterministic workflows selected by `--focus` and shared by
  one-shot CLI and REPL;
- five AI-promoted comprehensive tools; focused semantic views and all Catalog
  commands remain AI-invisible;
- FortiOS IKE/IPsec key-material redaction before parsing;
- `docs/fortios-semantic-coverage.md` with concrete coverage and Supported
  readiness criteria.

## Verification completed

- 337 tests pass with 86.89% coverage;
- Ruff format/check and strict mypy pass for 110 source files;
- semantic parser variants cover healthy/degraded/down, malformed, reordered,
  empty, unsupported, prompt-injection, secret, and truncation paths;
- typed Evidence round-trips through SQLite schema version 1 without migration;
- HA, explicit disabled SD-WAN, IPsec, and OSPF paths were verified on authorized
  FortiOS 7.2.13 hardware without configuration or raw-output persistence;
- empty live BGP output remains controlled missing Evidence rather than a false
  disabled/healthy result;
- a native OAuth semantic AI attempt failed safely before a tool call with
  `CODEX_OAUTH_OUTPUT_INVALID`; deterministic and `FakeAIProvider` verification
  remain green;
- final catalog drift, pre-commit, Markdown, secret/vendor-source, Git, push, and
  CI evidence are recorded by the completion report rather than assumed here.
