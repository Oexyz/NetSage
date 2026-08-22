# Optional Codex App Server Provider

Provider ID: `codex-app-server`

NetSage can reuse an installed official Codex CLI as an optional OpenAI-backed
reasoning runtime. It is no longer required for ChatGPT subscription access: the
separate experimental [`openai-codex`](openai-codex.md) provider implements a
native device-code flow. This adapter uses the documented `codex app-server` JSONL protocol;
it does not execute `codex exec`, scrape terminal output, read Codex auth files,
or copy ChatGPT tokens.

Official reference:

- [Codex App Server](https://developers.openai.com/codex/app-server)

## Selection and authentication

```text
explicit codex-app-server or auto fallback with codex on PATH
  -> Codex App Server
  -> Codex-managed ChatGPT/API authentication

codex absent from PATH
  -> this optional provider is unavailable
```

Check the selected runtime with:

```powershell
netsage ai status
```

When Codex is installed but not authenticated, run:

```powershell
codex login
```

NetSage does not turn an App Server authentication/runtime failure into an
invisible potentially billable API request. It reports a bounded error. Native
OAuth and direct API authentication remain separate provider choices.

## Security boundary

The App Server is launched only as a reasoning adapter:

- Codex owns and refreshes its authentication; NetSage requests only minimal
  account status and discards email identity fields.
- No auth token, cookie, auth file, API key, or refresh token is read or copied.
- Each reasoning thread is ephemeral and starts in a new empty temporary
  directory, outside the NetSage repository and application state.
- The child environment is allowlisted and excludes arbitrary environment
  variables, API keys, device passwords, and credential-bearing proxy URLs.
- Shell, unified execution, MCP, apps, plugins, skills, browser, computer use,
  image tools, and subagents are disabled in the App Server configuration.
- Turns use read-only sandboxing with tool-network access disabled.
- Any server-initiated tool or approval request, or any completed tool item,
  causes the provider turn to fail closed.
- Only sanitized `AIContext`, Broker-owned semantic tool metadata, and typed
  Evidence/tool results enter the prompt.

Codex never connects to a network device. A structured request for additional
network evidence returns as JSON to the provider-neutral `AgentRuntime`, which
validates it and routes it through the same `ToolBroker` and vendor driver used
by every provider.

## Structured response

The adapter supplies a strict JSON Schema to `turn/start`. The wire response is
validated by Pydantic and converted into the same `AIFinalResponse` or
`AIToolCallsResponse` used by the direct API and `FakeAIProvider`. Markdown JSON
and unvalidated text have no fallback path.

App Server errors, timeouts, invalid output, and forbidden tool attempts are
reported as bounded error categories. Raw provider errors, reasoning, protocol
transcripts, and final model text are not persisted.
