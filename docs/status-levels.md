# NetSage Feature Maturity Levels

NetSage uses five maturity labels. They describe the current maintained scope of
an area, not the age of its code and not the maturity of the whole product.

## Supported

The documented scope is implemented, maintained as a NetSage contract, covered
by substantial automated tests, and protected by tested security boundaries. It
has been reused across multiple milestones and has no known fundamental design
gap.

Supported does not mean bug-free, production-ready, or API-stable forever.
NetSage is alpha software, so pre-1.0 interfaces may still evolve. Incompatible
changes to a Supported area should nevertheless have a concrete reason,
migration consideration, tests, and matching documentation.

## Beta

The area is functional and practically usable, has meaningful automated tests,
and has at least partial live or end-to-end verification. Compatibility breadth
across devices, firmware, accounts, operating systems, or environments is still
limited, so additional edge cases are expected.

## Experimental

The area depends on an unstable or compatibility-oriented external interface,
has limited real-world verification, or may require significant contract changes.
Experimental is not the default label for newly written functionality.

## In Development

Implementation work is materially present or active, but the area is not yet
usable enough to call Beta. Empty packages, placeholders, and architecture notes
alone do not qualify.

## Planned

The area exists in the product architecture or roadmap but has no usable
implementation. Placeholder packages remain Planned until real implementation
work begins.

## Alpha lifecycle

NetSage Alpha is functional and testable, with Supported internal foundations,
Beta device/provider capabilities, and explicitly isolated Experimental
integrations. Alpha does not mean stable, production-ready, enterprise-ready, or
version 1.0.

## Current decision record

Status review performed on 2026-08-22 against the live source, 286 automated
tests, 86.50% coverage, successful CI history, security canaries, standalone
builds, and authorized live verification recorded in project documentation.

| Status | Areas | Basis |
|---|---|---|
| Supported | Developer foundation; core models and contracts; Security Broker and ObservePolicy; credential isolation and profiles; secure local state; SSH trust; persistent History and Audit; Evidence foundation; provider-neutral AI boundary; bounded AgentRuntime; interactive shell | Stable internal contracts, broad automated/security tests, and repeated use across milestones |
| Beta | FortiGate/FortiOS read-only driver and onboarding; deterministic FortiOS investigations; FortiOS command knowledge; safe catalog execution; OpenAI API provider; optional Codex App Server provider | Functional and tested with partial live/end-to-end validation, but compatibility breadth is limited |
| Experimental | Native Codex OAuth compatibility provider | Strong implementation and live verification, but its upstream third-party compatibility behavior is not a guaranteed stable contract |
| In Development | None currently | No partially implemented area is presented as usable; placeholders remain Planned |
| Planned | Additional AI providers and vendors; Discovery; Topology; Vantage Points; Probes; MCP/Web; Plan/Apply; automatic remediation | Architecture or placeholders only; no usable implementation |

The generated FortiOS catalog's 19,030/19,030 source coverage is command-knowledge
coverage for FortiOS 7.2.13. It is not 100% FortiOS product support. Likewise,
Supported security components remain subject to security review and defect
reporting; the label is not a claim that security bugs are impossible.
