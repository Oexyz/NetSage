# Provider-neutral AI Boundary

NetSage implements a typed security boundary, deterministic FakeAIProvider, an
experimental installed-Codex adapter, and a direct OpenAI API fallback. Codex
owns its managed authentication and NetSage never receives its tokens. The API
fallback key is stored separately in the OS credential store and is consumed
only by the trusted official SDK client. See
[Codex provider](providers/codex.md) and [OpenAI provider](providers/openai.md).

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

## Real provider transport

OpenAI receives the same semantic contract as FakeAIProvider. The adapter
serializes only AIContext, the Broker-filtered StructuredTool catalog, and typed
prior tool results. The Responses API uses a Pydantic Structured Output envelope,
`store=false`, and an empty built-in-tools list.

Tool names in model output are data for AgentRuntime, not OpenAI function tools.
Raw provider responses, SDK errors, hidden reasoning, request transcripts, and
provider authentication are not persisted.
