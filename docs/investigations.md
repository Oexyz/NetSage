# Deterministic Investigations

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

FortiGate support remains experimental. One authorized live verification does not
establish universal FortiOS compatibility.

The complete health-investigation flow has been live-verified against an
authorized FortiOS 7.2.13 device. The verification persisted no credential,
device address, hostname, interface data, evidence payload, or raw capture.
