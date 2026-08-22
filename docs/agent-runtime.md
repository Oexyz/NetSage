# Bounded Agent Runtime

Maturity: Supported

`AgentRuntime` is ordinary typed Python without LangChain, CrewAI, AutoGen, or
another agent framework. FakeAIProvider remains the deterministic test provider;
native Codex OAuth, the optional Codex App Server, and the direct OpenAI API all
implement the same contract. AgentRuntime does not know which isolated provider
authentication domain is active.

## Loop

```text
build sanitized AIContext
  -> provider typed response
  -> final assessment OR bounded typed tool calls
  -> Broker and Evidence collection
  -> rebuild context
```

The loop stops on a validated final response, provider failure, repeated call,
step limit, per-step tool limit, or total tool limit. Conservative defaults are:

- 8 agent steps;
- 20 total tool calls;
- 4 tool calls per step.

Exact repeated tool name plus arguments without new Evidence terminates the run.
Tool-call UUIDs must also be unique.

FortiOS HA, SD-WAN, IPsec, BGP, and OSPF status can enter the loop only when the
provider requests the corresponding Broker-owned semantic tool. A normal health
baseline does not pre-collect all domains. Each collection is bounded; truncated
status remains explicit, and focused views which cannot preserve that state fail
closed.

## Final validation

`AIFinalResponse` separates summary, qualitative DiagnosisStrength, Evidence UUIDs,
and limitations. No percentage confidence exists. All Evidence references must
belong to the current Investigation. CONFIRMED, STRONG, and PROBABLE require
Evidence. If deterministic analysis is already CONFIRMED, the AI response must
also be CONFIRMED and include its Evidence references.

The provider-neutral report renders deterministic findings and AI assessment as
separate sections and always states that no configuration changed.

## Current status

The provider-neutral AgentRuntime is a Supported NetSage contract. It is proven
with scripted FakeAIProvider and fake native OAuth/App Server/API client loops,
failures, malicious tool requests, prompt injection, and limit tests. Concrete
provider maturity is classified separately: OpenAI API and Codex App Server are
Beta, while native Codex OAuth is Experimental. `netsage ask` follows the visible
provider selection policy; `netsage investigate` remains deterministic. Provider
raw responses, hidden reasoning, API keys, tokens, and request transcripts are
not persisted.

Automated semantic-tool loops use `FakeAIProvider`. The milestone's native OAuth
live attempt returned a typed invalid-output provider failure before requesting a
tool; no semantic Evidence or raw device data was returned to that failed turn.
