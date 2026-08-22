# FortiOS Read-Only Catalog Execution

Maturity: Beta

NetSage provides an expert execution layer for a conservative subset of the
generated FortiOS catalog. It is not raw CLI and is separate from Investigation,
Evidence, and AI tool promotion.

## Measured promotion

All 1,049 READ_ONLY definitions receive one generated disposition:

| Disposition | Count |
|---|---:|
| Safely executable | 515 |
| Requires review | 362 |
| Non-executable from available syntax | 172 |

The executable subset consists only of complete, one-line, non-contextual,
non-sensitive, unambiguous leaf definitions with safely renderable syntax and no
broad string or enum/boolean mode argument. Side-effect terms, interactive/debug
streams, command-tree parents, sensitive paths/arguments, incomplete conversion
syntax, and unrenderable definitions fail closed.

Diagnostics are not promoted through this layer. The two existing reviewed ping
and traceroute operations remain available only through their existing semantic,
policy-controlled driver tools. All 2,758 DIAGNOSTIC definitions remain denied by
default for `fortios run`; CONFIGURATION and DESTRUCTIVE executable counts are
both zero.

## Execution pipeline

```text
logical Device ID + trusted Catalog Command ID + named arguments
  -> manifest lookup
  -> execution disposition
  -> ObservePolicy
  -> typed argument validation
  -> safe renderer
  -> existing FortiOS runtime and SSH transport
  -> existing credential resolution and host-key pinning
  -> paging, timeout, and transport output limit
  -> known-secret and pattern redaction
  -> terminal-control filtering and executor output limit
  -> CatalogCommandResult (UNTRUSTED_DEVICE_DATA)
  -> secret-free Audit metadata
```

`FortiOSCatalogExecutor` never receives a username, password, Credential object,
keyring, or host-key bypass. The stored runtime verifies the host key before
credential resolution and builds the same `FortiOSSSHTransport` used by existing
semantic operations. The transport independently repeats manifest lookup and
rejects every non-promoted/non-READ_ONLY ID before credential resolution.

## CLI and REPL

Dry-run performs local lookup, policy, argument, and rendering checks without
resolving credentials or contacting a device:

```powershell
netsage fortios run firewall-example fortios.execute.cpu.show --dry-run
```

Execute a promoted definition:

```powershell
netsage fortios run firewall-example fortios.execute.cpu.show
```

Pass typed named arguments only:

```powershell
netsage fortios run firewall-example COMMAND_ID --arg ip=192.0.2.10
```

Use `--json` for structured metadata and sanitized output. The same commands work
inside the existing NetSage REPL without the leading `netsage` word.

The command never accepts a complete user-supplied FortiOS string. Inputs such as
`show system status` at the REPL root remain unknown NetSage commands.

## Result, Audit, and persistence

Successful execution returns:

- command and logical device IDs;
- `READ_ONLY` classification and execution timestamp/duration;
- `SANITIZED_TEXT` output type;
- redacted, output-bounded text marked `UNTRUSTED_DEVICE_DATA`;
- `ai_visible=false`, `persisted=false`, `evidence_created=false`, and
  `configuration_changed=false`.

The text output is displayed or returned as JSON and then discarded. It is not
stored in Investigation History and is not converted into Evidence. Audit stores
the stable tool name `fortios_catalog:<command_id>`, logical device ID,
classification decision, safe named values, result category, and duration. It
never stores rendered CLI, raw/sanitized output, credentials, or transport
exceptions.

## Bounded failures

The public layer exposes only bounded categories:

```text
UNKNOWN_COMMAND
NOT_EXECUTABLE
POLICY_DENIED
INVALID_ARGUMENT
RENDER_FAILED
TRANSPORT_FAILED
OUTPUT_REDACTION_FAILED
OUTPUT_LIMIT_EXCEEDED
INTERACTIVE_UNSUPPORTED
TIMEOUT
AUDIT_FAILED
```

No raw SSH error, command output, or secret is interpolated into these errors.

Promotion establishes that a definition is safe to attempt, not that every
FortiGate model/build exposes it. A model-unavailable or permission-restricted
command fails with a bounded transport category and safe Audit event; NetSage
does not retry through raw CLI or another command.

Semantic observability is a separate promotion decision. Three reviewed,
argument-free Catalog IDs can be reached only through fixed Driver methods and a
closed semantic enum; their text is immediately parsed into typed Evidence. They
do not increase the 515-command expert subset, cannot be selected by a user or
AI, and do not make `SANITIZED_TEXT` Evidence. See
[FortiOS semantic coverage](fortios-semantic-coverage.md).
