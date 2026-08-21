# Provider-neutral AI Boundary

NetSage currently implements a typed security boundary and a deterministic
FakeAIProvider. No real AI service, authentication, endpoint, API key, or network
request exists.

## AI-visible context

`AIContext` contains only:

- investigation UUID and sanitized user request;
- logical device ID, platform, and capabilities;
- typed AIEvidence with ID, source device, operation, capability, timestamp,
  payload, and explicit `UNTRUSTED_DEVICE_DATA`;
- deterministic findings and missing-evidence descriptions.

It excludes Inventory dumps, host/management address, CredentialReference,
username, password, keyring metadata, SSH trust, database path, AuditEvent,
CommandResult, raw CLI, transport errors, and internal exceptions.

`AIContextBuilder` constructs this allowlisted view field by field. Before a
provider receives it, the existing SecretRedactor checks the complete serialized
context. A recognized secret raises `UnsafeAIContextError`; the builder does not
silently redact and continue.

Device-controlled content such as an interface description remains present only
inside typed AIEvidence and retains the untrusted marker. It is data, never an
instruction or authorization source.

## Tools and results

StructuredTool carries name, description, Capability, OperationClass, and typed
parameters. The catalog comes from ToolBroker registrations filtered for the
selected Device, declared Capability, and current ObservePolicy. A provider cannot
add tools.

AIToolCall uses a UUID, registered tool name, and validated arguments. Device ID
is injected by AgentRuntime. Results follow:

```text
AIToolCall -> ToolBroker -> CommandResult -> EvidenceCollector
           -> EvidenceEnvelope -> AIToolResult/AIEvidence
```

The provider never receives CommandResult or raw device output. Unknown, shell,
credential, malformed, unavailable, unsupported, and denied requests produce
bounded result categories.
