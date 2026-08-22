# Evidence Model

Maturity: Supported

NetSage evidence is an immutable, point-in-time snapshot created only after a
structured tool result has passed the Tool Broker. The evidence layer does not
resolve credentials, open network connections, select vendor commands, or store
raw CLI output.

## Pipeline

```text
NetworkDriver
  -> structured Tool Broker
  -> redacted CommandResult
  -> EvidenceFactory
  -> typed EvidenceEnvelope
  -> InMemoryEvidenceStore
```

`EvidenceEnvelope` records a UUID, investigation UUID, logical device ID,
structured operation, capability, timezone-aware UTC timestamp, trust
classification, typed payload, and non-secret provenance. Device evidence always
retains `UNTRUSTED_DEVICE_DATA`; normalization never turns device-controlled text
into instructions.

Provenance now also records the semantic parser schema version, selected parser
variant, and Parsed/Partial state. It never records the rendered FortiOS command
or raw output. Defaults preserve loading of Evidence written before these fields
were introduced.

## Typed payloads

The payload is a discriminated union rather than arbitrary JSON. The current
closed set covers normalized:

- device facts;
- interfaces;
- VLANs;
- ARP entries;
- routes;
- system health;
- IPv4 firewall policies;
- HA status and identity-safe members;
- bounded normalized HA history events and checksum non-sync scope comparisons;
- SD-WAN status, members, and health checks;
- IPsec status and tunnels with Phase 1/Phase 2 state;
- BGP status and neighbors;
- OSPF status and neighbors;
- derived route summaries;
- policy-authorized ping and traceroute results.

Each wrapper contains the existing vendor-neutral Pydantic model or a tuple of
those models. The envelope validates that payload, capability, operation,
provenance, and device identity agree. Unknown result shapes and unsupported
operations fail closed.

The new comprehensive semantic status payloads are explicitly bounded and carry
`truncated=true` when the parser has more valid records than the model can hold.
Focused member/neighbor/tunnel operations reject a truncated source instead of
silently returning a partial tuple. Empty or unrecognized feature output becomes
`EvidenceCollectionFailure`; only an explicit FortiOS disabled/not-running state
becomes a successful payload with `enabled=false`.

HA diagnostic payloads never contain raw history lines, configuration values, or
checksum fingerprints. History member identities are replaced with `member-N`
aliases, and HA status/member Evidence applies the same aliasing before storage.
Unknown history lines retain only the `UNKNOWN` event type. HA history is limited
to 2,048 normalized events and checksum comparison state to 128 scope results;
parser input limits and any truncation remain explicit in Evidence.

## Provenance and trust

Provenance contains only the structured tool, logical device ID, capability,
platform, driver name, and `structured_broker_tool` collection method. It excludes
host addresses, usernames, credential references, passwords, keys, tokens, SSH
host-key material, and raw transport details.

## Redaction and storage

The Broker redacts tool results first. `EvidenceFactory` applies the existing
`SecretRedactor` again before validating the typed payload. The in-memory store
performs a final rejection check and refuses evidence containing a recognized or
explicitly known secret. It accepts only `EvidenceEnvelope` instances and rejects
duplicate evidence IDs.

Collection failure is not evidence. `EvidenceCollectionFailure` records only a
safe phase, exception class name, and bounded category. Raw exception messages
and device output are never copied. This distinction allows an investigation to
differentiate a successfully observed empty route table from a route collection
that failed.

The in-memory store remains available for unit tests and `--ephemeral` mode.
Normal stored Device investigations persist the same typed envelopes through
`SQLiteEvidenceStore`; loading revalidates the discriminated payload union. Raw
capture storage remains intentionally unimplemented. The semantic expansion uses
the existing History schema: older Evidence variants remain loadable, and the
new discriminators round-trip without a database migration.

HA Audit details contain only the normalized event/mismatch count and truncation
flag. Raw history and checksum output never enter Audit, SQLite, or terminal
history. See [FortiOS HA diagnostics](fortios-ha-diagnostics.md).

The administrator-facing FortiOS compatibility report is intentionally not
Evidence and is not persisted in Investigation History. It characterizes parser
and capability availability without making a health finding or entering AI
context.
