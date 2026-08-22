# FortiOS HA Diagnostic Correlation

Maturity: Supported-quality semantic boundary within the Beta FortiOS driver

NetSage performs HA root-cause narrowing deterministically from typed Evidence.
It does not send raw HA diagnostic text to an AI model and does not ask an LLM to
guess why a cluster is unhealthy.

## Staged collection

`netsage investigate DEVICE --focus ha` uses three bounded stages:

1. Always collect normalized HA status and members.
2. Only after out-of-sync, degraded health, truncation, or a member anomaly,
   collect typed HA history and checksum non-sync state.
3. Only after heartbeat or membership instability, collect normalized interface
   state and correlate the heartbeat interfaces named by HA history.

A healthy synchronized cluster therefore does not run history, checksum, or
interface diagnostics.

The two deep operations are fixed, argument-free semantic promotions of existing
reviewed Catalog definitions:

| Operation | Trusted Catalog ID | Policy |
|---|---|---|
| `get_ha_history` | `fortios.diagnose.sys.ha.history.read` | Diagnostic; explicitly allowed only for the HA workflow |
| `get_ha_checksum_nonsync` | `fortios.diagnose.sys.ha.checksum.show-nonsync` | Diagnostic; explicitly allowed only for the HA workflow |

There is no wildcard `diagnose sys ha *` permission and no caller-provided
command, Catalog ID, or CLI fragment. The remaining Catalog diagnostics stay
denied by default.

## Typed evidence

HA history becomes a bounded `HAHistory` containing `HAEvent` values. Recognized
event types include heartbeat loss/restoration, heartbeat-interface down/up,
member left/join/rejoin, primary/failover, explicit member boot/restart, explicit
HA-process restart, and synchronization loss/restoration. Unrecognized lines
become `UNKNOWN`; they are not interpreted or persisted as free-form text.

Device member IDs and hostnames are collapsed to stable per-observation aliases
such as `member-1`. HA status Evidence applies the same aliasing defense in depth.
No serial number or member hostname is needed for correlation.

HA checksum output becomes `HAChecksumStatus`. It records only comparison state,
scope categories, compared/distinct counts, and mismatch count. VDOM names are
collapsed to the `vdom` category. Checksum fingerprints and configuration values
are deliberately discarded.

Limits are explicit:

- transport command timeout: 30 seconds by default;
- transport output safety ceiling: 5,000,000 characters;
- HA-history parser input: 1,000,000 characters;
- parsed HA events: 2,048;
- checksum parser input: 131,072 characters and 512 lines;
- checksum scope results: 128.

Every parser or model limit sets `truncated=true`; no silent clipping is treated
as complete Evidence.

## Time and episode correlation

FortiOS timestamps with an explicit offset remain offset-aware. Device-local
timestamps remain naive and are marked `DEVICE_LOCAL`; NetSage never invents a
timezone. Events without a reliable timestamp remain present with unknown time
and uncertain ordering.

Exact duplicate normalized events are removed. Distinct events at the same time
are retained. Timestamped incident events are grouped with a conservative,
testable five-minute correlation window. Temporal proximity is Evidence that
events occurred together; it is not represented as proof that one caused the
other.

## Findings and fault domains

The correlation layer uses the following bounded fault domains:

- `configuration_synchronization`;
- `ha_heartbeat_communication`;
- `ha_heartbeat_interface`;
- `member_restart`;
- `ha_process`;
- `cluster_membership`;
- `unknown`.

Direct FortiOS out-of-sync, explicit restart/boot, and a currently unavailable
interface can be `CONFIRMED` observations. Repeated heartbeat loss plus member
rejoin without physical evidence is `PROBABLE`. Heartbeat events plus correlated
interface down/up or error Evidence can narrow the link/interface fault domain
to `STRONG`.

`CABLE_FAILED` is not a NetSage fault domain. Even when an interface is down,
device Evidence normally cannot distinguish a cable, switch port, local port,
remote member hardware, or process problem. The report therefore keeps
`specific_physical_cause_confirmed=false` and lists missing Evidence such as:

- `heartbeat_interface_state_unavailable`;
- `member_restart_evidence_unavailable`;
- `ha_history_truncated`;
- `ha_history_unrecognized`;
- `checksum_detail_unavailable`;
- `heartbeat_physical_layer_unobservable`.

If HA status reports out-of-sync while the checksum comparison is equal at the
same collection stage, NetSage emits
`ha_synchronization_observations_disagree`. It preserves both direct Evidence
references and does not silently choose one source or fabricate a mismatch.

## Persistence, Audit, and AI boundary

Only `HAHistoryEvidencePayload`, `HAChecksumEvidencePayload`, normalized
interfaces, Findings, Diagnosis, and `HADiagnosticSummary` may enter History.
Raw history, raw checksum output, checksum fingerprints, command strings, member
serials, and member hostnames are not persisted.

Audit records the semantic operation, logical Device ID, success/failure,
duration, event or mismatch count, and truncation flag. It never records the
diagnostic output.

The two deep HA operations are Broker-only and `ai_visible=false`. AI context may
receive the resulting typed Evidence, deterministic Finding strengths, and
Missing Evidence. AgentRuntime rejects an AI attempt to raise a deterministic
`PROBABLE`/`STRONG` diagnosis without additional Evidence and preserves Evidence
references for deterministic `CONFIRMED` findings.

## Live validation and limitations

The staged workflow was verified read-only on an authorized FortiOS 7.2.13 HA
cluster with current configuration non-synchronization and repeated historical
heartbeat/member incidents. It automatically produced:

- `CONFIRMED` configuration out-of-sync;
- `PROBABLE` heartbeat communication instability;
- `STRONG` heartbeat link/interface fault-domain narrowing when normalized
  interface Evidence was available;
- no member-restart or HA-process-restart claim without an explicit event;
- no confirmed cable, port, peer, or other physical root cause.

No identifying live output or capture is stored in the repository. The synthetic
fixtures reproduce only minimal event grammar and fault patterns. FortiOS as a
whole remains Beta because other firmware/model/VDOM combinations and the BGP,
IPsec, active SD-WAN, and OSPF-adjacency gaps remain separate.
