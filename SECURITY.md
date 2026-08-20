# NetSage Security Model

NetSage is an early-stage defensive diagnostic tool. Version 0.1 is read-only and
does not support configuration changes.

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
messages. The current audit sink is in-memory only and is not persistent.

Evidence is created only from Broker-validated `CommandResult` objects. The
factory reuses `SecretRedactor`, retains typed normalized payloads and explicit
`UNTRUSTED_DEVICE_DATA`, and records only non-secret provenance. The in-memory
evidence store rejects values which still contain a recognized or explicitly
known secret. Collection failures record bounded categories rather than raw
exception messages. Evidence is not an audit log and contains no credential
reference or transport secret.

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
4. AI providers never receive API tokens.
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
