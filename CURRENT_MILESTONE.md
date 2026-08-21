# Current Milestone: AI Context & Agent Runtime Boundary Foundation

Status: complete. The provider-neutral context, typed tool boundary, bounded
runtime, FakeAIProvider, Evidence validation, and security controls are fully
verified without any external AI traffic.

## Goals completed

- immutable allowlisted AIContext and minimal AIDeviceContext;
- typed AIEvidence retaining explicit UNTRUSTED_DEVICE_DATA;
- fail-closed AIContextBuilder with defensive SecretRedactor checks;
- typed StructuredTool, AIToolCall, AIToolResult, and AIFinalResponse;
- Broker-derived tool catalogs filtered by Inventory, Capability, and ObservePolicy;
- Evidence-only AI tool results after Broker and EvidenceCollector;
- bounded AgentRuntime with conservative step/tool-call limits;
- duplicate-call and duplicate-call-ID handling;
- safe provider/tool error categories without internal exception strings;
- deterministic programmable FakeAIProvider only;
- final Evidence-reference validation and deterministic-CONFIRMED protection;
- provider-neutral report separating deterministic findings and AI assessment.

## Non-goals

- no Codex, OpenAI, Claude, Ollama, Gemini, OpenRouter, or real provider;
- no provider credentials, API keys, endpoints, login, network traffic, or raw responses;
- no new hardware or FortiOS commands;
- no Discovery, Topology, LLDP, probes, vantage points, MCP, Web UI, or FastAPI;
- no configuration planning, remediation, arbitrary shell, or arbitrary CLI;
- no agent CLI presented as a real AI product;
- no Retention, Backup, or database-encryption work.

## Security invariants

- AI receives no credential reference, username, password, host, management IP,
  SSH trust, keyring metadata, database path, Audit internals, raw CLI, raw
  CommandResult, or internal exception;
- device-controlled strings remain marked untrusted and cannot alter tools/policy;
- NetSage alone defines the exposed tool set;
- every requested operation still passes ToolBroker and ObservePolicy;
- diagnostics are never enabled by the provider;
- CONFIRMED/STRONG/PROBABLE require Evidence and unknown Evidence IDs fail;
- deterministic CONFIRMED conclusions cannot be structurally weakened;
- loops stop on final response, provider failure, repeat, step limit, or tool limit.

## Verification

- full routes -> health -> final FakeAI loop;
- shell, credential, and unknown tool denial;
- malformed arguments and policy-denied diagnostic handling;
- repeated calls, duplicate IDs, step and tool budgets;
- provider failures and invalid final responses;
- invalid/absent Evidence references and deterministic contradictions;
- prompt injection remains inert untrusted data;
- canary secrets and credential metadata remain outside AI-visible objects;
- all existing FortiOS, State, History, Audit, and CLI workflows remain green.

## Next milestone

Not selected. Do not begin a real AI provider automatically.
