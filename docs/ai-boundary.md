# Provider-neutral AI Boundary

NetSage implements a typed security boundary, deterministic FakeAIProvider, an
experimental native ChatGPT/Codex OAuth compatibility provider, an optional
installed-Codex adapter, and a direct OpenAI API provider. Native OAuth tokens
and the API key use different OS-keyring services; neither enters AIContext. See
[native Codex OAuth](providers/openai-codex.md), optional
[Codex App Server](providers/codex.md), and [OpenAI API](providers/openai.md).

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

## Real provider transports

Every provider receives the same semantic contract as FakeAIProvider. Each
adapter serializes only AIContext, the Broker-filtered StructuredTool catalog,
and typed prior tool results. Native Codex OAuth and the direct API use strict
structured output, `store=false`, and an empty built-in-tools list. The optional
App Server uses the same schema and rejects all server-owned tool requests.

Tool names in model output are data for AgentRuntime, not OpenAI function tools.
Raw provider responses, SDK errors, hidden reasoning, request transcripts, and
provider authentication are not persisted.

Native Codex OAuth authentication is a trusted transport concern. Its keyring
store and refresh client are not provider input and are not reachable as model
tools. The resulting bearer is restricted to the Codex compatibility backend;
the separate API provider can resolve only its own API-key service.
