# OpenAI Provider

NetSage's direct API fallback integrates the official OpenAI Python SDK and
Responses API. It has no dependency on Codex, Node.js, an external AI CLI, a
local App Server, or a provider-owned tool runtime. NetSage selects this path
only when no `codex` executable is installed on `PATH`; see the
[Codex provider](codex.md) for the preferred runtime.

Official references:

- [OpenAI API authentication and quickstart](https://platform.openai.com/docs/quickstart/make-your-first-api-request)
- [Structured Outputs](https://developers.openai.com/api/docs/guides/structured-outputs)
- [Models API](https://developers.openai.com/api/reference/python/resources/models/methods/list)
- [OpenAI model catalog](https://developers.openai.com/api/docs/models)

## Architecture

```text
sanitized AIContext + Broker-filtered tool metadata
  -> OpenAIProvider
  -> official AsyncOpenAI client
  -> Responses API with store=false and no tools
  -> Pydantic Structured Output
  -> AgentRuntime
  -> optional NetSage AIToolCall
  -> ToolBroker -> FortiOS driver -> Evidence
```

OpenAI never receives network-device credentials, Inventory, SSH trust, raw CLI,
CommandResult objects, local file paths, or a device management address. The API
key is passed only to the trusted SDK client and is not part of provider input.

## Fallback authentication

```powershell
netsage ai openai login
```

Use this command when `netsage ai status` reports that Codex is absent. It opens
the official OpenAI API-key page unless `--no-browser` is used,
then accepts the key through a hidden prompt. NetSage validates it with the Models
API before writing it to the operating-system credential store under the separate
service name `NetSage OpenAI Provider`.

The key is never accepted as a CLI argument or environment-variable fallback and
is never written to NetSage YAML, Inventory, History, Audit, Evidence, reports, or
logs. The network-device credential profiles remain a separate domain.

The public OpenAI API documentation specifies API-key authentication. The direct
fallback does not copy a ChatGPT subscription or Codex sign-in. When Codex is
installed, NetSage instead talks to the official App Server and lets Codex own
its documented managed authentication flow.

Useful commands:

```powershell
netsage ai openai status
netsage ai openai models
netsage ai openai logout
```

Logout deletes only the provider-specific OS-keyring entry.

## Model selection

Models are listed from the authenticated API project. The current non-sensitive
defaults are:

```yaml
ai:
  provider: openai
  openai:
    model: gpt-5.6-terra
    reasoning_effort: medium
```

Change them with:

```powershell
netsage ai openai configure --model MODEL --effort medium
netsage ai openai configure --defaults
```

The selected model must appear in the authenticated project's model list before
an AgentRuntime starts.

## Structured response and tools

The official SDK derives a strict response format from the Pydantic
`OpenAIStructuredOutput`, which contains exactly one provider-neutral
`AIFinalResponse` or `AIToolCallsResponse`. NetSage does not parse JSON from
Markdown and has no unvalidated free-text fallback.

The API request supplies an empty `tools` list. Web search, file search, MCP,
code interpreter, computer use, shell, and other OpenAI built-in tools are not
available. A requested NetSage tool name exists only inside the structured model
response; AgentRuntime validates it and ToolBroker remains the sole execution
authority.

Responses use `store=false`. Raw provider responses, reasoning, SDK errors, API
keys, and provider request transcripts are not persisted.

## Ask workflow

```powershell
netsage ask DEVICE "Check for obvious health or routing issues."
```

When Codex is absent, `ask` validates API authentication and model availability, then builds
the deterministic FortiOS baseline and runs the bounded AgentRuntime. The existing
`netsage investigate DEVICE` command remains AI-independent and deterministic.

## Troubleshooting

- `OPENAI_NOT_AUTHENTICATED`: run `netsage ai openai login`.
- `OPENAI_AUTHENTICATION_FAILED`: create or verify an API key in the official
  OpenAI platform and run login again.
- `OPENAI_MODEL_UNAVAILABLE`: choose a model shown by
  `netsage ai openai models`.
- `OPENAI_TIMEOUT`: the API request exceeded its bound.
- `OPENAI_API_ERROR`: the official API or network request failed safely.
- `OPENAI_OUTPUT_INVALID`: no validated structured response was returned.
- `OPENAI_CREDENTIAL_STORE_ERROR`: the OS credential backend is unavailable.

Direct API usage and billing are separate from a ChatGPT subscription. The provider
remains experimental; one test environment does not establish production
readiness or universal model availability.
