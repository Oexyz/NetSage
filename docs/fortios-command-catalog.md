# FortiOS Command Catalog

NetSage maintains a generated FortiOS 7.2.13 CLI knowledge catalog derived from
the complete local `fortios.md` conversion. The catalog is metadata, not a raw
device execution surface.

## Coverage

The current source-derived inventory contains:

| Area | Definitions |
|---|---:|
| Documented configuration/diagnose/execute topics | 4,972 |
| Additional complete diagnose/execute table syntaxes | 232 |
| Documented configuration-context commands | 13,826 |
| Total discovered and catalogued | 19,030 |

The exact class, execution, and parser totals are generated in
[FortiOS command coverage](fortios-command-coverage.md). Catalog coverage means
`KNOWN + CLASSIFIED + POLICY-AWARE + SOURCE-TRACEABLE`. It does not mean every
command is executable or has a typed output parser.

The converted 7.2.13 reference contains authoritative CLI sections for
configuration, diagnose, and execute commands. It does not contain separate
`get` or `show` command-reference sections. NetSage's existing fixed `get/show`
driver operations therefore remain in the reviewed transport allowlist and are
not invented as source-derived catalog entries or included in these counts.

The extractor does not trust the topic lists alone: it also compares every
command-like syntax row and includes 232 complete operational paths omitted from
those lists. Fifty-five truncated/prose rows are explicitly accounted for as
conversion/non-command artifacts; they are not silently discarded or invented as
commands.

Every READ_ONLY definition now also has a generated execution disposition. Of
1,049 entries, 515 are promoted to bounded `SANITIZED_TEXT`, 362 require review,
and 172 are non-executable from available syntax. The two existing structured
`execute ping` and `execute traceroute` paths remain typed semantic diagnostics,
not Catalog Executor promotions. All diagnostics remain denied by default.

See [FortiOS catalog execution](fortios-catalog-execution.md) for the execution,
redaction, audit, and persistence boundaries.

## Source and generation

`fortios.md` is a 7 MB PDF-to-text conversion rather than conventional Markdown.
The extractor reads all source bytes and logical lines, identifies the
configuration, diagnose, and execute sections, normalizes converted table rows,
and maps every documented topic path to a syntax occurrence. It also walks the
configuration grammar to capture scoped `config`, `edit`, `set`, `next`, and
`end` definitions. Other verbs are included only when they occur as actual
command syntax; prose mentions are not promoted into definitions.

Generate and verify with:

```powershell
uv run python scripts/generate_fortios_catalog.py
uv run python scripts/generate_fortios_catalog.py --check
```

The compressed runtime manifest is deterministic and marked `DO NOT EDIT
MANUALLY`. It records the source SHA-256, byte/line totals, FortiOS version, and a
line/page reference for every definition. Runtime commands load the generated
manifest lazily; starting `netsage` does not parse the reference.

The Fortinet reference is intentionally excluded by `.gitignore` and is not
published in this open-source repository. When it is locally present, tests run
the full source-to-manifest drift comparison. CI, where the copyrighted source is
absent, validates the generated manifest, schema, internal totals, and generated
coverage document. Vendor description prose is used transiently for conservative
classification but is not copied into the generated artifact.

## Classification

Every entry has one operation class:

- configuration roots and scoped `set/edit/config/next/end` definitions are
  `CONFIGURATION`;
- scoped `delete/purge` and operational commands with destructive semantics such
  as reboot, restart, reset, remove, restore, firmware, format, or clear are
  `DESTRUCTIVE`;
- show/list/status/info/read/view/dump-style operations are `READ_ONLY` when the
  path or source description establishes observational behavior;
- remaining diagnose/execute operations are conservatively `DIAGNOSTIC`.

This is semantic and conservative rather than a prefix-only rule. For example,
`execute reboot` and `diagnose ... clear` are destructive, while an
`execute ... show` command can be read-only. Uncertain commands default to a
denied class rather than being treated as safe.

Capability mapping covers interfaces, VLAN, MAC, ARP, routes, LLDP, firewall,
VPN/IPsec/SSL VPN, BGP, OSPF, DNS, DHCP, sessions, HA, SD-WAN, logs, system
health, ping, and traceroute where the path supports a reliable mapping.

## Arguments and rendering

Placeholders are normalized into typed argument metadata including IP/IPv4/IPv6,
network, integer, enum, boolean, hostname, interface, VDOM, policy ID, port,
protocol, and conservative string values. Sensitive password/secret/token
placeholders are identified and are never renderable.

The registry renderer accepts only named arguments declared by one known
definition. IPs and networks use Python address parsing; integers and ports are
bounded; enums must match source choices; strings use a restrictive token
character set. Newlines, shell separators, substitutions, and unexpected
arguments fail closed. Rendering is local review functionality and does not add
a transport method.

## Local inspection

These commands never access a device:

```powershell
netsage fortios commands search bgp
netsage fortios commands show fortios.execute.ping
netsage fortios commands coverage
```

The complete catalog is not sent to AI context. AgentRuntime continues to see
only the small Broker-filtered structured tool catalog for the selected device
and investigation scope.
