# FortiOS Semantic Compatibility

Maturity: Beta

The compatibility probe answers one question:

> Can NetSage reliably observe this semantic area on the selected FortiOS
> device?

It is not an Investigation and does not decide whether the network is healthy.
It performs no configuration, remediation, discovery, scanning, or AI call.

## Command

```powershell
netsage device test DEVICE
netsage fortios compatibility DEVICE
netsage fortios compatibility DEVICE --json
netsage fortios compatibility DEVICE --export report.json
```

The same compatibility handler works inside the NetSage REPL:

```text
netsage> fortios compatibility DEVICE
```

`--force` is required to replace an existing regular export file. Symbolic-link
targets are refused.

## Bounded architecture

```text
logical Device ID
  -> existing host-key and credential runtime
  -> ToolBroker / ObservePolicy / Audit
  -> ten sequential semantic operations
  -> normalized Pydantic results or categorized failures
  -> typed compatibility report
  -> terminal OR anonymized JSON/export
```

The ten operations are fixed:

1. Device facts
2. System health
3. Interfaces
4. Route summary
5. Firewall policies
6. HA status
7. SD-WAN status
8. IPsec status
9. BGP status
10. OSPF status

The probe does not execute the 515 expert commands or iterate the 19,030-entry
catalog. Operations run sequentially. An authentication, host-key, connection,
timeout, or output-limit failure on the first operation stops further collection
to avoid repeated login/load attempts.

## Capability states

| State | Meaning |
|---|---|
| `SUPPORTED` | The non-feature semantic parser returned a valid normalized result |
| `ENABLED` | FortiOS directly supported an enabled feature observation |
| `DISABLED` | FortiOS explicitly reported the feature disabled/not running |
| `NOT_CONFIGURED` | FortiOS explicitly reported no configuration |
| `UNAVAILABLE` | A command/capability/runtime was not safely available |
| `PERMISSION_DENIED` | The read-only profile could not execute the operation |
| `OUTPUT_UNRECOGNIZED` | Empty or changed output could not be interpreted safely |
| `PARTIAL` | Some normalized structure exists, but required compatibility evidence is incomplete |

Parser states are independently `PARSED`, `PARTIAL`, `UNRECOGNIZED`, or
`NOT_APPLICABLE`. No numerical parser confidence is generated.

## Firmware and variants

`FortiOSVersion` parses major, minor, and patch numerically, plus optional build,
branch point, and release data. An unknown patch is represented as `x` and never
matches a bounded concrete range. String ordering is not used.

BGP and OSPF have two reviewed variants each for the conservative
reference-validated FortiOS 7.0 through 7.6 range:

| Operation | Primary | Bounded fallback |
|---|---|---|
| BGP | `get router info bgp summary` | `get router info bgp neighbors` |
| OSPF | status plus `get router info ospf neighbor all` | status plus `get router info ospf neighbor` |

Fallback occurs only for `COMMAND_UNAVAILABLE`, `EMPTY_OUTPUT`, or
`OUTPUT_UNRECOGNIZED`. Permission denial, authentication, host-key failure,
timeout, output limit, and transport failure stop immediately. Explicit
Disabled/Not Configured results are successful observations and do not trigger a
fallback. No AI or user string can select a variant.

The reviewed commands and output shapes were checked against Fortinet's official
[BGP route/neighbor guidance](https://community.fortinet.com/fortigate-3/technical-tip-how-to-check-bgp-advertised-and-received-routes-on-a-fortigate-98156),
[OSPF neighbor guidance](https://community.fortinet.com/fortigate-3/troubleshooting-tip-unable-to-see-ospf-neighbor-no-hello-packets-132780),
and [routing diagnostic reference](https://community.fortinet.com/fortigate-3/technical-tip-fortigate-routing-debug-commands-177121).

## VDOM boundary

The report records only:

- single, multi, or unknown VDOM mode;
- global, root, specific, or unknown context category;
- the advertised maximum VDOM count when present.

It never stores a specific VDOM name. The probe does not run `config vdom`,
`edit`, or another generic context-changing sequence. Results describe the
current trusted CLI context only.

## Privacy and export

Terminal output may display the local logical Device ID. JSON and file exports
are always anonymized and use `fortios-device` instead. The normalized model
family is retained because it is compatibility-relevant; exact host identity is
not.

Reports contain:

- report schema and NetSage versions;
- typed FortiOS firmware/build metadata;
- normalized model family;
- VDOM category;
- area states, parser states, error categories, and reviewed variant IDs;
- a SHA-256 reproduction fingerprint which excludes Device ID and timestamp.

Reports never contain:

- management, interface, route, peer, BGP, OSPF, or VPN addresses;
- hostname, serial number, VDOM name, username, or CredentialReference;
- network password, SSH key, OAuth token, OpenAI API key, or IPsec key material;
- raw or sanitized CLI output.

## Parser/test matrix

`UNIT_FIXTURE` means minimal synthetic fixtures. `REFERENCE_VALIDATED` means the
shape/command was compared with the local ignored 7.2.13 source or official
Fortinet material. `LIVE` means the area was exercised on the authorized target.

| Area | Covered variants | Sources |
|---|---|---|
| System | percentage/totals memory, sessions, limits, conserve state, uptime, optional fields | UNIT_FIXTURE, LIVE |
| Interfaces | physical, VLAN, aggregate, loopback, tunnel, missing physical state, counters, unknown fields, injection text | UNIT_FIXTURE, LIVE |
| Routing | single/multiple/default/ECMP, inactive, static/connected/BGP/OSPF/unknown origin | UNIT_FIXTURE, LIVE |
| Firewall | disabled, missing logtraffic, NAT/ippool, multiple interfaces/services, schedule/comments/injection | UNIT_FIXTURE, LIVE |
| HA | standalone, A-P, A-A, two/multi-member, out-of-sync, legacy roles, partial member data | UNIT_FIXTURE, REFERENCE_VALIDATED, LIVE |
| SD-WAN | disabled, not configured, enabled/no checks, alive/dead, SLA pass/fail, partial metrics, multiple records | UNIT_FIXTURE, REFERENCE_VALIDATED, disabled-state LIVE |
| IPsec | none/partial/up/down, multiple tunnels/selectors/SAs, IPv4/IPv6 peers, NAT-T, ADVPN/dial-up-safe unknown fields, key canaries | UNIT_FIXTURE, REFERENCE_VALIDATED, LIVE |
| BGP | Established, Idle, Connect, Active, OpenSent, OpenConfirm, unknown, zero/missing prefixes, summary/detailed, empty/denied/unavailable | UNIT_FIXTURE, REFERENCE_VALIDATED; live output unrecognized |
| OSPF | Down, Attempt, Init, 2-Way, ExStart, Exchange, Loading, Full, unknown, VRF/header/role spacing, empty/denied/unavailable | UNIT_FIXTURE, REFERENCE_VALIDATED; process LIVE |

Unknown safe fields are ignored. Missing optional values remain `None`/Unknown.
Structural corruption or an unreviewed firmware range produces a categorized
failure rather than empty strings, zeros, or a random fallback.

## Current live matrix

Only actually observed combinations are listed:

| FortiOS | Context | Area | Validation |
|---|---|---|---|
| 7.2.13 | single VDOM / root | System | LIVE: supported |
| 7.2.13 | single VDOM / root | Interfaces | LIVE: supported |
| 7.2.13 | single VDOM / root | Routing | LIVE: supported |
| 7.2.13 | single VDOM / root | Firewall | LIVE: supported |
| 7.2.13 | single VDOM / root | HA | LIVE: enabled/parsed |
| 7.2.13 | single VDOM / root | SD-WAN | LIVE: disabled/parsed |
| 7.2.13 | single VDOM / root | IPsec | LIVE: enabled/partial |
| 7.2.13 | single VDOM / root | BGP | LIVE: output unrecognized after two variants |
| 7.2.13 | single VDOM / root | OSPF | LIVE: enabled/parsed; no adjacency available |

No absent feature was configured for testing.

## Supported-readiness matrix

| Criterion | State | Evidence/gap |
|---|---|---|
| Transport | READY | Pinned, bounded and live verified |
| Credential isolation | READY | Keyring/trusted-runtime boundary and canaries |
| Host-key trust | READY | Changed-key rejection and live verification |
| System semantics | READY | Variant fixtures and live report |
| Interface semantics | READY | Type/state/counter variants and live report |
| Routing semantics | READY | Active/inactive/default/ECMP/origin variants and live report |
| Firewall semantics | READY | Policy/NAT/list/optional variants and live report |
| HA semantics | READY | Standalone/A-P/A-A/partial matrix and live report |
| SD-WAN semantics | PARTIAL | Disabled-state live; active/SLA live path unavailable |
| IPsec semantics | PARTIAL | Live enabled result remains parser-partial |
| BGP semantics | GAP | Fixture/reference matrix passes; live output remains unrecognized |
| OSPF semantics | PARTIAL | Process live; no live adjacency state |
| Version compatibility | PARTIAL | Typed/range-aware; only 7.2.13 live |
| Model compatibility | PARTIAL | One authorized model family live |
| VDOM compatibility | PARTIAL | Safe categories/unit matrix; only single/root live |
| Permission handling | PARTIAL | Categorized and unit-tested; restricted-profile live matrix incomplete |

## Readiness decision

**KEEP BETA.**

The architecture now supports reproducible community-safe compatibility reports,
version-aware bounded fallback, permission-aware failures, and explicit unknown
states. Promotion still requires resolving or characterizing the live BGP output,
reducing IPsec partial parsing, and collecting representative active SD-WAN,
OSPF-adjacency, multi-VDOM, restricted-permission, and additional model/version
reports.
