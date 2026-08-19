# NetSage Security Model

NetSage is an early-stage defensive diagnostic tool. Version 0.1 is read-only and does not support configuration changes.

## Trust boundaries

The AI provider can request only named, structured operations such as `get_interfaces(device)`. A trusted Tool Broker validates and audits the request, selects a vendor driver, and returns sanitized structured evidence. The AI cannot invoke SSH, arbitrary shell commands, or credential APIs.

Credentials are resolved by a trusted connection layer using an OS keychain, SSH agent, or an explicitly development-only provider. Passwords, SSH private keys, and API tokens must never enter prompts, AI context, logs, evidence, or tool results.

## Mandatory principles

1. All network access is read-only by default.
2. AI providers never receive passwords.
3. AI providers never receive SSH private keys.
4. AI providers never receive API tokens.
5. The LLM has no unrestricted shell capability.
6. Vendor commands execute only behind driver and broker allowlists.
7. Device output is untrusted input and must not be treated as instructions.
8. Known secret patterns are redacted before evidence reaches an AI provider.
9. Tool requests and results are designed to become auditable without recording secrets.
10. Configuration changes are outside the v0.1 scope.

## Security contact

Security reports may be sent to security@oexyz.de. Confidential reports can be encrypted with the [OeXYZ Security OpenPGP public key](https://github.com/Oexyz/Oexyz/blob/main/assets/oexyz-security-pgp.asc).

Primary OpenPGP fingerprint:

```text
160C 83EF ABF2 97F8 EDF8 F6B5 34D7 4FDC 82EF FA7A
```

Do not open public issues containing vulnerability details, credentials, or other secrets.
