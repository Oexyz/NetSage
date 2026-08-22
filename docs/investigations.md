# Deterministic Investigations

Maturity: Beta for the implemented FortiOS workflows

The current investigation foundation runs fixed Python workflows without an AI
provider, prompt engine, rule-engine dependency, or direct driver access.

```text
Investigation
  -> ToolBroker.invoke(...)
  -> EvidenceCollector
  -> EvidenceEnvelope or safe collection failure
  -> deterministic findings
  -> optional diagnosis
  -> human-readable report
```

## Domain semantics

- `Investigation` identifies one immutable workflow run and its scope.
- `Finding` records an observed condition; it is not automatically a root cause.
- `Diagnosis` is optional and references evidence UUIDs rather than copying data.
- `DiagnosisStrength` is limited to `CONFIRMED`, `STRONG`, `PROBABLE`, and
  `INSUFFICIENT`. No numerical confidence is generated.
- `InvestigationReport` keeps evidence references, collection failures, findings,
  and diagnosis separate and always states that no configuration changed.

The same synthetic inputs produce the same findings and diagnosis. Tests inject
identifier and clock sources where deterministic metadata is required.

## Implemented FortiOS workflows

### Health

Collects facts, interfaces, system health, and routes through the Broker. It can
report measured high CPU or memory, administratively disabled interfaces,
operationally down enabled interfaces, and a missing active IPv4 default route.
CPU and memory thresholds are shared with the existing normalized health status:
75% is degraded and 90% is unhealthy.

Resource utilization and disabled interfaces remain findings. They are not
automatically declared root causes. A missing active default route can be
confirmed only when route collection succeeded.

### Default route

Collects the normalized route table. A successful empty result confirms that no
active IPv4 default route was observed. A failed or unsupported collection
instead produces `INSUFFICIENT` with explicit missing evidence.

### Interface state

Collects normalized interfaces and reports administrative and operational state.
An enabled but operationally down interface is reported exactly as observed. The
workflow does not claim that a cable is unplugged or invent another physical
cause.

### HA health

Collects bounded HA status and members. Direct FortiOS out-of-sync or degraded
health state can produce `CONFIRMED` operational findings without inventing the
reason for synchronization or failover problems. A single observed member is a
warning because expected cluster membership is not known.

### SD-WAN health

Collects members and health-check paths only for the explicit SD-WAN focus.
FortiOS-reported dead state and explicit SLA failure are findings. NetSage does
not invent latency, jitter, or loss thresholds. When every observed path is dead,
the observed absence of an alive path is `CONFIRMED`; the underlying cause is not.

### IPsec health

Collects Phase 1, Phase 2, SA state and interfaces. A down Phase 1 or an
established Phase 1 without an active Phase 2 is reported exactly as observed;
NetSage does not infer a PSK, ISP, peer, or firewall cause. A down tunnel plus a
down bound interface can produce `STRONG` cross-domain fault-domain evidence.
Key material is neither parsed nor persisted.

### Dynamic-routing health

Collects BGP and OSPF only for the explicit routing focus. It reports BGP
non-established state, established peers with zero received prefixes, OSPF
neighbors that are not FULL, and enabled processes with no observed neighbors.
Empty BGP summary output remains missing Evidence because it can be ambiguous.

## Partial evidence

Tool failures are isolated. A health investigation can retain successful facts,
interfaces, and health evidence when route collection fails, but the overall
diagnosis becomes `INSUFFICIENT`. Failure records contain bounded categories, not
raw output or arbitrary exception messages.

## CLI

The minimal live workflow is:

```powershell
uv run netsage fortigate investigate
```

It reuses the existing host-key pinning, hidden process-memory-only credential
flow, FortiOS transport, structured Broker tools, and redaction controls. It does
not persist evidence or raw output and performs no configuration operation.

The existing passive compatibility check remains available as:

```powershell
uv run netsage fortigate live-test
```

Deterministic FortiOS investigations are Beta. They are tested and live-verified,
but the implemented investigation breadth and device/firmware matrix remain
limited.

The deterministic Device-ID command accepts an optional bounded focus:

```powershell
netsage investigate DEVICE --focus health
netsage investigate DEVICE --focus ha
netsage investigate DEVICE --focus sdwan
netsage investigate DEVICE --focus ipsec
netsage investigate DEVICE --focus routing
```

The same syntax works in the NetSage REPL without the leading `netsage` word.
The default remains `health`, preserving existing behavior. The separate
`netsage ask DEVICE "question"` command runs the same deterministic
health baseline first and then supplies sanitized Evidence to the selected AI
provider. The official OpenAI API and optional Codex App Server adapters are
Beta; native Codex OAuth is Experimental. A provider may name only an operation
from the Broker-filtered structured catalog in its typed response; AgentRuntime
executes any accepted request and validates the final Evidence references. See
[native Codex OAuth](providers/openai-codex.md),
[Codex App Server](providers/codex.md), and [OpenAI API](providers/openai.md).

The complete health-investigation flow has been live-verified against an
authorized FortiOS 7.2.13 device. The verification persisted no credential,
device address, hostname, interface data, evidence payload, or raw capture.

Representative HA, disabled SD-WAN, IPsec, and OSPF focused workflows were also
verified live. BGP was not asserted as disabled when the target returned an empty
summary; the routing workflow retained OSPF Evidence and reported BGP as missing.
The native OAuth semantic-tool verification was attempted but failed safely
before a tool call with a typed provider-output error, so automated semantic AI
verification continues to rely on `FakeAIProvider`.

Stored Device-ID investigations now persist sanitized Report, Evidence, and safe
Audit metadata locally by default. `netsage investigations` and
`netsage investigation show UUID` reload typed reports without a device
connection. `netsage investigate DEVICE --ephemeral` writes no History rows.
