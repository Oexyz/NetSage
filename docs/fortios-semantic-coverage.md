# FortiOS Semantic Coverage

Maturity: Beta

This matrix describes normalized semantic support. It is separate from the
19,030-definition FortiOS command-knowledge catalog and the 515-command expert
`SANITIZED_TEXT` execution subset. No percentage is assigned because command,
model, firmware, and troubleshooting coverage do not share a meaningful common
denominator.

## Implemented matrix

| Area | Semantic operations | Typed Evidence | Deterministic findings | Live verification |
|---|---:|---|---|---|
| System | Existing `get_device_facts`, enriched `get_system_health` | Facts and health, including optional session/conserve state | Resource and explicit health state | Existing FortiOS 7.2.13 verification |
| Interfaces | Enriched `get_interfaces` | State, addresses, VLAN/parent, role, duplex, optional counters/errors | Administrative/operational state and IPsec interface correlation | Existing FortiOS 7.2.13 verification |
| Routing | Existing `get_routes`, new `get_route_summary` | Routes and derived route summary | Active default and equal-cost summary without reachability claims | Existing route collection verified |
| Firewall | Enriched `get_firewall_policies` | Direction, addresses, service, action, NAT, schedule, enabled and log-traffic state | Existing policy-presence/state analysis | Existing policy collection verified |
| HA | `get_ha_status`, `get_ha_members`, `get_ha_history`, `get_ha_checksum_nonsync` | Mode, health, alias-only members, bounded history events, checksum comparison scopes | Staged config-drift, heartbeat/member, interface, restart/process, and insufficient physical-cause findings | Status, history, checksum, interface correlation and synchronization verified |
| SD-WAN | `get_sdwan_status`, `get_sdwan_members`, `get_sdwan_health_checks` | Bounded members, health-check paths, FortiOS-reported SLA state and metrics | Dead path, explicit SLA failure, no alive path, healthy alternative | Explicit not-running state verified; active paths not available on target |
| IPsec | `get_ipsec_status`, `get_ipsec_tunnels` | Bounded Phase 1, Phase 2, peers, SA state and counters; no key material | Phase 1 down, Phase 2 absent, established state and interface correlation | Enabled live; parser state partial |
| BGP | `get_bgp_status`, `get_bgp_neighbors` | Router/local-AS and bounded summary/detailed neighbors | Not established, all FSM states, zero/missing received/advertised prefixes | Two reviewed live variants exhausted; output unrecognized |
| OSPF | `get_ospf_status`, `get_ospf_neighbors` | Process identity and bounded neighbors | Full OSPF FSM state set and no-neighbor observation | Process enabled/parsed live; no adjacency available |

Fourteen semantic operations are implemented. Five comprehensive
status operations are AI-promoted: HA, SD-WAN, IPsec, BGP, and OSPF. Focused
collection views and route summary remain Broker operations but are not included
in the AI catalog.

## Collection and compatibility behavior

- HA members are limited to 64.
- HA history is limited to 1,000,000 source characters and 2,048 normalized
  events; checksum input is limited to 131,072 characters/512 lines and 128
  scope results.
- SD-WAN members are limited to 256 and health-check records to 512.
- IPsec Phase 1 and tunnel collections are limited to 256; each tunnel can carry
  at most 512 Phase 2 records.
- BGP and OSPF neighbor collections are limited to 512.
- Comprehensive status models set `truncated=true` when a source exceeds a
  limit. Focused views fail with a controlled incomplete-collection error rather
  than silently dropping that flag.
- Explicit FortiOS disabled/not-running messages become `enabled=false`.
- Explicit Disabled and Not Configured are distinct `FeatureState` values.
- Empty or unrecognized output remains missing Evidence when it is ambiguous.
- A model-, version-, permission-, VDOM-, or license-specific command rejection
  becomes a bounded collection failure, not a fabricated empty result.
- Parser provenance records schema, selected variant, attempted variants, and
  Parsed/Partial state without storing a command string.

The administrator-facing
[compatibility probe and matrix](fortios-compatibility.md) characterize these
states without creating Investigation findings or adding data to AI context.

Five read-only definitions reuse trusted generated catalog IDs behind a fixed
semantic enum: HA history, HA checksum non-sync, SD-WAN health checks, IKE
gateway status, and IPsec tunnel status. The HA pair is registered as diagnostic
Broker operations and explicitly policy-enabled only for staged HA investigation.
HA, SD-WAN member, BGP, and OSPF observations use separate fixed reviewed Driver
requests because the source catalog either lacks the relevant `get` command or
contains only debug-status syntax. Callers still cannot provide a command string.

The reviewed output shapes were cross-checked against Fortinet's official
[HA synchronization](https://docs.fortinet.com/document/fortigate/7.6.6/administration-guide/63913/check-ha-synchronization-status),
[routing diagnostics](https://community.fortinet.com/fortigate-3/technical-tip-fortigate-routing-debug-commands-177121),
[SD-WAN status](https://community.fortinet.com/fortigate-3/technical-tip-configure-and-diagnostic-commands-to-check-the-status-of-the-sd-wan-link-96317),
and [IPsec troubleshooting](https://community.fortinet.com/fortigate-3/troubleshooting-tip-ipsec-vpn-tunnels-97751)
material. The local ignored 7.2.13 CLI source remains the command-syntax and
classification reference and is not republished.

## Evidence and AI boundary

Each operation returns a Pydantic model through `CommandResult`, ToolBroker,
`EvidenceFactory`, and a discriminated `EvidenceEnvelope`. Device-controlled
names and identifiers remain `UNTRUSTED_DEVICE_DATA`; HA member identities are
collapsed to `member-N` aliases. Raw CLI, Catalog IDs,
credentials, management addresses, and transport objects are not AI inputs.

The five AI-visible tools describe what they observe and what they do not prove.
Collections are added to context only when requested during the bounded agent
loop; a normal health investigation does not automatically collect every domain.
Automated AI tests use `FakeAIProvider`. The milestone's native OAuth live check
failed safely before a semantic tool call with a typed provider-output error, so
it is not counted as successful live AI verification.

## FortiOS Supported Readiness

Recommendation: **KEEP BETA**. The detailed objective matrix is maintained in
[FortiOS compatibility](fortios-compatibility.md).

The following criteria are substantially implemented:

- stable Device-ID onboarding and pinned SSH transport;
- credential resolution inside the trusted runtime boundary;
- read-only semantic core observability across the target domains;
- typed, bounded and persistent Evidence;
- deterministic feature-focused investigations;
- graceful missing/unsupported output handling;
- no configuration or arbitrary-command surface;
- broad fixture, security, AgentRuntime, persistence and mass-catalog regression
  tests.

Remaining evidence before a Supported promotion:

- representative verification across more FortiGate models and FortiOS builds;
- live active SD-WAN members, health checks and explicit SLA failure variants;
- live BGP established and non-established neighbors;
- live OSPF FULL and non-FULL adjacencies;
- broader IPsec variants such as dial-up and ADVPN without selecting user or key
  material;
- additional HA firmware/model/VDOM history and checksum variants beyond the
  live 7.2.13 case;
- repeated operational use demonstrating that firmware, VDOM, permission and
  license differences fail gracefully.
