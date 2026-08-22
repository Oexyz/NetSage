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
- policy-authorized ping and traceroute results.

Each wrapper contains the existing vendor-neutral Pydantic model or a tuple of
those models. The envelope validates that payload, capability, operation,
provenance, and device identity agree. Unknown result shapes and unsupported
operations fail closed.

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
capture storage remains intentionally unimplemented.
