# NetSage Security Model

NetSage is an alpha defensive diagnostic tool. Version 0.1 is read-only and does
not support configuration changes. Supported security components are maintained,
tested NetSage contracts; this maturity label is not a claim that security bugs
are impossible or that the overall product is production-ready.

## Trust boundaries

The AI provider can request only named, structured operations such as
`get_interfaces(device)`. The Tool Broker validates the tool, device, declared
capability, authorization policy, and result identity before returning redacted,
structured device data. The AI cannot invoke SSH, arbitrary shell commands, or
credential APIs.

Credentials are resolved by a trusted connection layer. Password profiles use the
operating-system keyring; SSH-agent and development-environment providers remain
fail-closed stubs. Passwords, SSH private keys, API tokens, SNMP communities, and
AAA shared secrets must never enter prompts, AI context, state files, logs,
evidence, audit events, or tool results.

The generated FortiOS command catalog contains knowledge and policy metadata and
does not add a generic command-string transport method. Exactly 515 conservatively
promoted READ_ONLY definitions can reach the expert executor by Catalog ID and
validated named arguments. Another 362 require review and 172 are explicitly
non-executable. All diagnostics remain denied by default through this layer;
configuration and destructive executable counts are zero.

Dry-run performs lookup, disposition, ObservePolicy, typed validation, and
rendering before host verification or credential resolution. Actual execution
reuses the pinned existing runtime/transport; the transport independently repeats
manifest checks before resolving credentials. Sensitive/incomplete/contextual/
interactive/ambiguous definitions, broad strings and enum mode arguments, control
characters, separators, substitutions, pipes, and unexpected names fail closed.
Output is bounded, double-redacted, terminal-control filtered, marked untrusted,
and discarded after terminal/JSON delivery. Only stable command ID, safe named
arguments, decision, result category, and duration enter Audit; output never
enters Evidence, History, logs, or AI context.

The semantic FortiOS layer is a separate reviewed surface. Twelve typed
operations cover HA, SD-WAN, IPsec, BGP, OSPF, and route summary; five
comprehensive status operations are AI-visible. Three source-traceable commands
use fixed Catalog IDs behind an argument-free enum, while the remaining commands
use the closed Driver request enum. No caller can supply a rendered command or
Catalog ID. The 515 expert commands remain AI-invisible and are not Evidence.

Semantic collections have hard item limits and explicit truncation. Focused
views fail when they cannot preserve truncation state. Feature/model/version
differences become bounded collection failures, and ambiguous empty output is not
converted into a fabricated disabled or healthy state.

The FortiOS compatibility probe invokes only ten existing semantic Broker tools,
sequentially. It never executes the 515 expert commands. BGP/OSPF have at most
two reviewed variants; only command-unavailable, empty, or unrecognized output
can trigger the second variant. Permission, authentication, host-key, timeout,
output-limit, and transport failures stop fallback. No privilege escalation or
generic VDOM context command exists.

Terminal compatibility output may show the local logical Device ID. JSON and
file exports are always anonymized and contain no management/interface/route/
peer/neighbor/VPN address, hostname, serial, VDOM name, username,
CredentialReference, device password, SSH key, OAuth token, OpenAI API key,
IPsec key material, or raw CLI. The normalized model family and typed firmware
are retained because they are the compatibility subject. Export uses restrictive
same-directory temporary files and atomic replacement; existing files require
explicit `--force`, and symbolic-link targets are refused.

The interactive `netsage` prompt dispatches only registered commands through the
same Typer tree as one-shot CLI calls. Unknown input is never forwarded to the
operating system. NetSage uses no `os.system`, `shell=True`, or generic subprocess
fallback for REPL input, and persists no shell history.

## Persistent local state

NetSage stores only non-secret, schema-versioned application settings, Inventory,
credential-profile metadata, and SSH host fingerprints under the current user's
platform-appropriate configuration directory. State writes use restrictive
same-directory temporary files, fsync, and atomic replacement. Invalid YAML and
unknown schema versions fail without modifying the file.

Credential profiles contain provider, kind, and username metadata. The username
is treated as operational metadata; the password is a separate runtime
`Credential` stored under keyring service `NetSage`. List and show operations do
not resolve it. If the OS backend is unavailable, NetSage fails closed and never
falls back to plaintext YAML, environment variables, or command-line flags.

## SSH host identity

Persistent SSH trust records contain only logical trust ID, host, port, public-key
algorithm, and SHA-256 fingerprint. Before authentication, NetSage rediscovers the
current public host key without sending a credential, compares it to persistent
trust, and uses the matching in-memory public key as AsyncSSH pinning material.
A changed key aborts; it is never silently replaced. Rotation requires the
separate `device trust-reset` workflow and explicit confirmation.

Tool results are explicitly marked as untrusted device data. Redaction removes
known secret fields and patterns, but it does not turn hostnames, descriptions,
banners, or logs into instructions. Audit events store safe arguments and bounded
status categories; they intentionally omit raw tool output and arbitrary exception
messages. Stored Device investigations use append-only SQLite Audit; ephemeral
flows retain the in-memory sink.

Evidence is created only from Broker-validated `CommandResult` objects. The
factory reuses `SecretRedactor`, retains typed normalized payloads and explicit
`UNTRUSTED_DEVICE_DATA`, and records only non-secret provenance. The in-memory
evidence store rejects values which still contain a recognized or explicitly
known secret. Collection failures record bounded categories rather than raw
exception messages. Evidence is not an audit log and contains no credential
reference or transport secret. In-memory Evidence remains available for
ephemeral workflows; normal Device-ID investigations can persist the same typed,
sanitized envelopes locally.

FortiOS IKE and IPsec output receives additional defense-in-depth redaction for
`key`, `SK_ei`, `SK_er`, `SK_ai`, `SK_ar`, and per-SA `key=<length>` material
before parsing. Semantic models never select those fields. Tests verify that
these values do not reach CommandResult, Evidence, History, Audit, AI context,
terminal output, or JSON serialization.

## Persistent operational history

`history.sqlite3` is stored beside the existing user-level state. It may contain
sensitive operational data including normalized IP addresses, interfaces, routes,
VLANs, ARP entries, firewall policies, health observations, findings, and
diagnoses. It never contains raw CLI output, Credential material, keyring secrets,
private keys, auth headers, or resolved credential references.

History is protected by the operating system's user-level file permissions, not
application-level database encryption. POSIX uses a `0700` state directory and
`0600` database; Windows relies on the current user's Local AppData ACL. NetSage
does not upload, synchronize, or send telemetry from History.

Broker Audit is append-only through the normal application API and stores safe
arguments, result categories, authorization decisions, durations, and bounded
details. It never stores CommandResult output. Deleting an Investigation cascades
its Evidence but retains Audit. No automatic Audit retention policy exists yet.

Normal `investigate DEVICE` persists sanitized Report, Evidence, and Audit by
default. `--ephemeral` selects in-memory Evidence and Audit and creates no History
rows. Persistent write failures are surfaced and never silently downgraded to an
in-memory fallback.

## AI runtime boundary

The Supported provider-neutral runtime receives an explicit allowlisted
AIContext rather than Inventory, database rows, CommandResult, AuditEvent, or
transport objects. The context excludes hosts, credential references, usernames,
keyring metadata, SSH trust, and internal exceptions. Device observations remain
typed `UNTRUSTED_DEVICE_DATA`.

Tool catalogs originate only from the Tool Broker and are filtered by Device
Capability and ObservePolicy. Unknown, shell, credential, and denied diagnostic
requests cannot expand that catalog. AI tool results contain Evidence—not raw
CommandResult output. Hard step/tool limits and duplicate-call protection prevent
unbounded loops. Final non-insufficient conclusions require valid current
Evidence references and cannot structurally contradict an existing deterministic
CONFIRMED diagnosis.

FakeAIProvider remains deterministic and offline. The experimental native
`openai-codex` provider can authenticate through the currently compatible
ChatGPT/Codex device-authorization flow without a Codex executable. Access,
refresh, and ID tokens are stored as one atomically activated, size-safe
generation of OS-keyring records under service `NetSage AI OpenAI Codex`; they
never enter NetSage files, SQLite, Audit,
Evidence, reports, logs, AIContext, or CLI output. In-process refreshes are
serialized and a complete replacement bundle is written only after successful
validation. OAuth headers and raw auth/inference responses are never logged.

Those OAuth credentials are sent only to the isolated Codex compatibility
backend. They are never used against `api.openai.com/v1/responses`. NetSage
identifies itself as NetSage, follows no authentication redirects, keeps TLS
verification enabled, supplies no provider-owned tools, uses `store=false`, and
bounds request time and streamed output. This compatibility is experimental and
is not described as an officially guaranteed third-party OAuth API.

An installed official Codex App Server remains a separate optional provider and
continues to own its managed authentication. NetSage receives only minimal
account status and never reads or copies App Server tokens. Codex runs an
ephemeral thread in an empty temporary directory with a scrubbed environment,
built-in tools disabled, read-only/no-tool-network sandboxing, and protocol-level
denial of tool and approval requests.

The Beta `openai-api` provider uses the official Python SDK and
Responses API with API-key authentication. The key is stored under a
separate provider-specific OS-keyring service, never in the network-device
CredentialProfile layer, YAML, SQLite, Audit, Evidence, logs, or AIContext.
NetSage has no environment-variable or plaintext fallback.

OpenAI requests set `store=false`, provide no built-in tools, and request a typed
Pydantic Structured Output. Web/file search, MCP, shell, code interpreter,
computer use, and provider-owned function execution are not exposed. NetSage
AgentRuntime interprets a structured tool-name request as data and ToolBroker
remains the only execution authority.

Only sanitized AIContext, Broker-filtered tool metadata, and typed Evidence/tool
results are serialized to OpenAI. Host/management address, username,
CredentialReference, network password, SSH trust, raw CLI, CommandResult,
Inventory, and History paths remain excluded. Raw App Server/SDK requests or
responses, provider errors, hidden reasoning, tokens, API keys, and final AI
assessments are not persisted.
Compatibility reports are administrator/test metadata and are not added to
AIContext or the AI tool catalog. The AI-visible FortiOS surface remains exactly
the five comprehensive semantic status tools; focused and compatibility views
remain AI-invisible.
NetSage never reads browser sessions, cookies, or browser tokens. A compatible
Codex `auth.json` can be copied into NetSage keyring storage only after explicit
user confirmation; detection checks file presence only, import does not modify
the source, and native login is preferred to avoid refresh-token races. See the
[native Codex OAuth boundary](docs/providers/openai-codex.md), optional
[Codex App Server provider](docs/providers/codex.md), and separate
[OpenAI API provider](docs/providers/openai.md).

The FortiOS live-test path discovers the SSH server key before asking for a
credential and pins that key in memory after explicit user confirmation. Its
password provider is process-memory-only: credentials cannot be supplied through
command-line arguments or environment variables and are not written to files,
keyrings, inventory, raw-output captures, logs, or audit events. Python cannot
guarantee in-place zeroing of immutable strings, so this path minimizes their
lifetime and is intended only for bounded authorized testing.

## Mandatory principles

1. All network access is read-only by default.
2. AI providers never receive passwords.
3. AI providers never receive SSH private keys.
4. AI model contexts never receive API tokens; only the trusted provider transport
   may consume its own API credential.
5. The LLM has no unrestricted shell capability.
6. Vendor commands execute only behind driver and broker allowlists.
7. Device output is untrusted input and must not be treated as instructions.
8. Known secret patterns are redacted before evidence reaches an AI provider.
9. Tool requests and results are auditable without recording secrets or raw output.
10. Configuration changes are outside the v0.1 scope.

## Security contact

Security reports may be sent to security@oexyz.de. Confidential reports can be encrypted with the [OeXYZ Security OpenPGP public key](https://github.com/Oexyz/Oexyz/blob/main/assets/oexyz-security-pgp.asc).

Primary OpenPGP fingerprint:

```text
160C 83EF ABF2 97F8 EDF8 F6B5 34D7 4FDC 82EF FA7A
```

Do not open public issues containing vulnerability details, credentials, or other secrets.
