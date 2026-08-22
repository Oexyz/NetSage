# Current Milestone: Status Reclassification & Alpha Readiness

Status: complete. This milestone changes documentation and maturity metadata
only; it introduces no product functionality. Publication is valid only when
the corresponding documentation commit is present on `main` and GitHub CI is
green.

## Published baseline

- `5754b98 docs: add intermittent WAN failure case study` is published and
  CI-green;
- `ee128e9 feat: add native Codex OAuth provider` is the separate feature commit
  immediately preceding this documentation milestone;
- `fortios.md` and the original vendor PDF remain local, ignored, and unpublished.

## Goal

- evaluate current maturity from live source, tests, CI, security verification,
  live validation, compatibility breadth, and known limitations;
- classify areas consistently as Supported, Beta, Experimental, In Development,
  or Planned;
- raise the overall project status from early development to Alpha if the
  repository evidence supports it;
- remove stale or contradictory maturity statements without changing product
  behavior.

## Decisions under validation

- Supported: maintained internal core, security, storage, Evidence, runtime, and
  interactive-shell contracts;
- Beta: usable FortiOS functionality and official OpenAI/Codex integrations with
  limited compatibility breadth;
- Experimental: native Codex OAuth compatibility because its upstream contract
  may change;
- In Development: none currently;
- Planned: placeholder- and roadmap-only areas.

The definitions and decision record live in `docs/status-levels.md`. Supported
means maintained and tested within the current alpha lifecycle; it is not a
production-readiness, bug-free, or pre-1.0 compatibility guarantee.

## Non-goals

- no new commands, parsers, investigations, providers, hardware, discovery,
  topology, vantage points, probes, MCP, Web UI, or configuration engine;
- no dependency, schema, protocol, or runtime behavior changes;
- no claim of stable, production-ready, enterprise-ready, universal FortiOS, or
  version 1.0 status.

## Completion evidence required

- README, AGENTS, SECURITY, provider/driver docs, and roadmap use the five status
  labels consistently;
- every Supported promotion is backed by relevant tests and established use;
- hardware/provider limitations remain explicit;
- Markdown tables, links, badges, and code blocks render correctly;
- full Ruff, strict mypy, pytest/coverage, pre-commit, secret/vendor-source checks,
  separate documentation commit, push, and GitHub CI pass.

## Verification completed

- the current repository evidence supports global Alpha status without a stable,
  production-ready, enterprise-ready, or 1.0 claim;
- Supported promotions are limited to maintained internal contracts with broad
  automated and security coverage and repeated cross-milestone use;
- FortiOS and official OpenAI/Codex integrations are Beta with compatibility
  breadth and provider-account limitations stated explicitly;
- native Codex OAuth remains Experimental because its upstream compatibility
  contract may change;
- placeholder-only providers, vendors, Discovery, Topology, Vantage Points,
  Probes, MCP/Web, and Plan/Apply remain Planned; none is mislabeled In Development;
- README and detailed documentation consistently use the five maturity labels;
- 23 changed Markdown files have zero broken internal links, unbalanced code
  fences, or malformed tables; the Alpha badge is present and the old badge is absent;
- 286 tests pass with 86.50% coverage; Ruff format/check, strict mypy for 101
  source files, catalog drift, and all pre-commit hooks pass;
- publishable files contain zero OAuth/device credential/live infrastructure,
  temporary device-code, or vendor-source matches;
- the only source-file change is a non-functional Evidence-store docstring
  correction; no product feature or runtime behavior changed.

## Next recommended milestone

After this documentation-only milestone, select one explicitly requested scope
from the roadmap. Do not begin another provider, vendor, or automation feature
automatically.
