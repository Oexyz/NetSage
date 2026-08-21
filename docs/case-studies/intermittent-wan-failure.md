# Case study: Intermittent WAN failure

## Context

NetSage was tested in a real authorized production vessel network. This case
study is intentionally anonymized. It contains no vessel or company names, IP
addresses, hostnames, serial numbers, interface names, credentials, or raw log
extracts.

This account describes a single operational validation, not a controlled
benchmark or a statistically representative performance claim. All durations
are approximate.

## Problem

Internet connectivity repeatedly failed only after several hours of operation.
The delayed and intermittent nature of the failure made it difficult to
reproduce during a short manual troubleshooting session.

## Investigation

NetSage was left running during normal operation and correlated the available
read-only observations, including:

- FortiGate logs;
- interface state;
- historical events;
- routing and broader network state;
- temporal relationships between connectivity failures and WAN events.

The correlation narrowed the likely fault domain to the physical WAN link,
including its cabling, after approximately five minutes of analysis. At that
stage the appropriate evidence-strength description was **STRONG**: the available
network observations pointed consistently to the physical link, but physical
inspection was still required.

## Result

A subsequent manual inspection confirmed that the WAN cable was faulty. The root
cause therefore moved from a strong evidence-backed indication to **CONFIRMED**.

| Measure | Result |
| --- | --- |
| Approximate NetSage analysis time | ~5 minutes |
| Estimated comparable manual troubleshooting effort | ~3 hours |
| Confirmed root cause | Faulty WAN cable |

The manual-effort figure is a case-specific estimate, not a general benchmark or
guaranteed time saving.

## Why this case matters

NetSage is not intended to replace experienced network administrators. Its value
in this case was the rapid correlation of logs, historical events, interface
state, routing state, and timing information. That correlation directed the
administrator to the relevant physical fault domain much sooner; the
administrator then verified the actual hardware fault.

This separation remains important: NetSage can assemble and evaluate evidence,
while a diagnosis that requires physical confirmation should not be presented as
confirmed until that verification has occurred.

## Operational boundaries

- The investigation was authorized and performed against a production vessel
  network.
- The case describes diagnostic observation, not automated remediation.
- No confidential infrastructure details or raw device output are published.
- No percentage is used as a calibrated probability or confidence claim.
