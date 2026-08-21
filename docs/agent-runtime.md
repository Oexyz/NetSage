# Bounded Agent Runtime

`AgentRuntime` is ordinary typed Python without LangChain, CrewAI, AutoGen, or
another agent framework. FakeAIProvider remains the deterministic test provider;
CodexProvider and OpenAIProvider implement the same contract through the
official Codex App Server and OpenAI Python SDK respectively.

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

## Final validation

`AIFinalResponse` separates summary, qualitative DiagnosisStrength, Evidence UUIDs,
and limitations. No percentage confidence exists. All Evidence references must
belong to the current Investigation. CONFIRMED, STRONG, and PROBABLE require
Evidence. If deterministic analysis is already CONFIRMED, the AI response must
also be CONFIRMED and include its Evidence references.

The provider-neutral report renders deterministic findings and AI assessment as
separate sections and always states that no configuration changed.

## Current status

The runtime is an experimental boundary proven with scripted FakeAIProvider,
fake App Server/API client loops, failures, malicious tool requests, prompt
injection, and limit tests. `netsage ask` prefers installed Codex and otherwise
uses the direct API; `netsage investigate` remains deterministic. Provider raw
responses, hidden reasoning, API keys, tokens, and request transcripts are not
persisted.
