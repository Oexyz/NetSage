# Persistent Audit Trail

Maturity: Supported

`SQLiteAuditSink` implements the existing `AuditSink` contract and records each
Broker decision by INSERT only. The normal application exposes no update, edit,
delete, or purge operation for Audit events.

Stored fields are limited to timestamp, user, optional AI-provider identifier,
structured tool, logical device, safe arguments, result category, duration,
authorization decision, bounded detail, and the enforced false values for
`configuration_changed` and `credential_exposed`.

Audit never stores raw CLI output, a CommandResult payload, Credential,
CredentialReference resolution, password, key, token, community, or auth header.
Before INSERT, safe arguments and all free strings are checked again with the
existing SecretRedactor. A persistence failure is surfaced; NetSage does not
silently fall back to an in-memory sink when persistent Audit was selected.

The AI-assisted `ask` workflow records Broker operations with the selected
stable provider ID (`openai-codex`, `codex-app-server`, or `openai-api`). Audit
does not store AIContext, prompts, output schemas, OAuth tokens, API keys,
authorization headers, App Server/HTTP/SDK requests or responses, reasoning, or
final model text.

Recent events are available without network access:

```powershell
netsage audit --limit 50
```

Promoted manual FortiOS catalog reads use stable tool names of the form
`fortios_catalog:<command_id>`. Audit stores the logical device, READ_ONLY
authorization, safe named arguments, result category, duration, and bounded error
code. It never stores the rendered CLI string or raw/sanitized command output.

There is no automatic retention or purge policy yet. Audit remains after an
Investigation and its Evidence are removed.
