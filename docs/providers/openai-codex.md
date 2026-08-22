# Experimental OpenAI Codex OAuth Provider

Provider ID: `openai-codex`

This provider offers experimental ChatGPT/Codex OAuth compatibility without
requiring Codex CLI, Node.js, a `.codex` directory, or an OpenAI API key. It uses
ChatGPT subscription-backed Codex access only where the current upstream account
and workspace permit it.

This is not documented as a stable officially guaranteed third-party OAuth API.
The integration may require updates when upstream behavior changes. The separate
[`openai-api`](openai.md) provider remains the supported API-key/billing route.

## References reviewed

The protocol was verified on 2026-08-22 against:

- [official OpenAI Codex authentication documentation](https://developers.openai.com/codex/auth);
- [OpenAI Codex source](https://github.com/openai/codex) at commit
  `4f39251a010a8bd7d692d25fb33832ff06f1635a`;
- [Hermes Agent](https://github.com/NousResearch/hermes-agent) at commit
  `9ddb6547a062a81510a943cc54f525c25cf63d8f`.

Hermes was used to validate behavior and interoperability. NetSage does not copy
Hermes code or adopt its plaintext auth-store design.

## Current compatibility protocol

All change-prone values are isolated in `openai_codex/protocol.py`.

```text
POST https://auth.openai.com/api/accounts/deviceauth/usercode
  -> device_auth_id, user_code, interval

Open https://auth.openai.com/codex/device
  -> user enters the one-time code

POST https://auth.openai.com/api/accounts/deviceauth/token
  -> authorization_code, code_verifier

POST https://auth.openai.com/oauth/token
  -> access_token, refresh_token, id_token
```

The device authorization request currently sends the public Codex OAuth client
identifier and no explicit scope parameter. The authorization server supplies
the PKCE verifier during the device flow; NetSage sends it only during the
authorization-code exchange. Polling honors the returned interval,
`authorization_pending`, `slow_down`, denial, and expiry.

Refresh uses the same token endpoint with `grant_type=refresh_token`. NetSage
refreshes shortly before access-token expiry and serializes concurrent refreshes
with an async lock. A rotated access/refresh/ID-token set is validated first and
then written as one complete, atomically activated keyring generation. A terminal refresh failure requires
`netsage ai codex login`; no retry loop is started inside AgentRuntime.

Inference uses:

```text
POST https://chatgpt.com/backend-api/codex/responses
```

The bearer access token and the account identifier from the trusted OAuth token
claims are attached only to that backend. NetSage identifies its originator as
`netsage`, follows no redirects, retains TLS verification, omits the provider
tool surface entirely, requests strict structured output, uses `store=false`, and bounds both HTTP
time and SSE response size. The bearer is never sent to
`api.openai.com/v1/responses`.

## Credential storage

All OAuth credential material is stored as one logical bundle in the
operating-system credential store. The bundle is split into bounded records for
platforms such as Windows Credential Manager; a small active-generation pointer
is switched only after every chunk has been written successfully:

```text
Service: NetSage AI OpenAI Codex
Active pointer: oauth-token-bundle-v1
Secret records: oauth-token-bundle-v1:<generation>:<chunk>
```

The bundle includes access, refresh, and ID tokens. It never enters
`config.yaml`, Inventory, credential profiles, `history.sqlite3`, Evidence,
Audit, reports, logs, AIContext, exceptions, or CLI output. Non-secret provider
selection and model preferences may remain in `config.yaml`.

This keyring domain is separate from:

- network-device credentials under `NetSage`;
- the OpenAI API key under `NetSage OpenAI Provider`.

## Commands

One-shot and REPL commands use the same handlers:

```text
netsage ai codex login
netsage ai codex status
netsage ai codex logout
netsage ai codex import-existing
```

Login prints the verification URL and one-time code. It opens the browser unless
`--no-browser` is used. Ctrl+C cancels without writing credentials.

Status reveals only configuration, authentication, token-validity/refresh state,
and experimental status. There is no token reveal or export command. Logout
deletes only the NetSage keyring entry; it does not change Codex CLI, browser, or
ChatGPT sessions.

## Existing Codex authentication

`import-existing` checks only whether a compatible Codex `auth.json` exists until
the user explicitly confirms import. After confirmation, NetSage extracts only
the required token fields, writes them to its own keyring entry, and never
modifies or deletes the source.

A separate native login is preferred. Refresh tokens can rotate, so independently
using an imported session in Codex and NetSage may invalidate one copy. Codex
keyring-only auth files are not imported; an installed Codex App Server can be
selected separately instead.

## Provider selection

The visible `auto` order is:

1. configured native `openai-codex` OAuth;
2. optional installed `codex-app-server` authentication;
3. configured `openai-api` key;
4. no AI provider.

Select a route explicitly when required:

```powershell
netsage ai configure --provider openai-codex
netsage ai configure --provider codex-app-server
netsage ai configure --provider openai-api
netsage ai configure --provider auto
```

`netsage ai status` shows the selected provider, authentication mode, and whether
access is subscription-backed or usage-based. NetSage never silently turns an
OAuth failure into a paid API request.

## Agent and network boundary

`CodexOAuthProvider` implements the existing `AIProvider` contract. It receives
the same sanitized AIContext and Broker-owned semantic tool metadata as every
other provider. Codex built-in shell, filesystem, MCP, web search, browser,
computer use, and function tools are absent. Any requested NetSage tool name is
structured output data for AgentRuntime; ToolBroker remains the only execution
authority.

Deterministic commands remain available without any AI authentication.

## Safe failures

- `CODEX_OAUTH_NOT_AUTHENTICATED`: run `netsage ai codex login`.
- `CODEX_OAUTH_AUTHENTICATION_EXPIRED`: refresh is no longer usable; log in again.
- `CODEX_OAUTH_LOGIN_UNAVAILABLE`: upstream device authorization is unavailable.
- `CODEX_OAUTH_RATE_LIMITED`: retry after the upstream limit resets.
- `CODEX_OAUTH_MODEL_UNAVAILABLE`: choose a compatible configured Codex model.
- `CODEX_OAUTH_INFERENCE_UNAVAILABLE`: the experimental backend path failed.
- `CODEX_OAUTH_OUTPUT_INVALID`: no bounded typed result was returned.
- `CODEX_OAUTH_CREDENTIAL_STORE_ERROR`: no safe OS keyring backend is available.

Errors never contain raw HTTP bodies, authorization headers, tokens, or provider
responses.
