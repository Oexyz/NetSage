# Network Drivers

NetSage drivers translate fixed semantic operations into vendor-specific,
read-only access and normalize the results. AI providers and Broker callers never
receive an SSH session, raw command string, or credential-provider API.

## FortiOS

The FortiOS implementation uses AsyncSSH with a closed command enum. Before any
credential is transmitted, the live CLI retrieves the SSH host key without
authentication, displays its SHA-256 fingerprint, requires explicit confirmation,
and pins the public key in memory for the connection. Host-key checking cannot be
disabled through the NetSage API.

Credentials are resolved by `FortiOSSSHTransport` immediately before connecting.
The interactive live test uses `EphemeralCredentialProvider`, which retains one
credential in process memory only. It does not write files, environment variables,
keyrings, inventory fields, logs, audit events, or command history. Python cannot
guarantee in-place zeroing of immutable strings, so the object lifetime is kept
bounded to the live operation.

### Command allowlist

| Semantic operation | Fixed command | Class |
|---|---|---|
| Device facts | `get system status` | Read-only |
| Interfaces | `show system interface` | Read-only |
| Physical interface state | `get system interface physical` | Read-only |
| ARP table | `get system arp` | Read-only |
| Active routes | `get router info routing-table all` | Read-only |
| System health | `get system performance status` | Read-only |
| IPv4 firewall policies | `show firewall policy` | Read-only |
| Ping | `execute ping <validated-IP>` | Diagnostic |
| Traceroute | `execute traceroute <validated-IP>` | Diagnostic |

Diagnostics accept only parsed IP address objects and are denied by the default
Observe policy. No user or AI string can become a FortiOS command.

The FortiOS CLI reference is used to review the fixed commands and their versioned
syntax. It is not bundled as an executable command catalog and is never exposed as
an arbitrary CLI tool. Adding a command to a future driver requires a semantic
capability, a read-only or explicitly controlled classification, normalized output,
redaction, and synthetic tests.

### Shell output handling

FortiOS can paginate long `show` and `get` output at `--More--`. The transport
opens a bounded interactive terminal, waits for the initial prompt, advances each
page with a space, and stops when the device prompt returns. It strips terminal
control and paging artifacts before parsing. NetSage does not run `config system
console` or change the global `output` setting, because that would mutate device
configuration and could affect other administrators.

Parsers accept prompt and command-echo variants, current-VDOM wrappers, omitted
default settings, nested configuration blocks, and common FortiOS appliance model
names. The current milestone is still a deliberately bounded FortiOS 7.x-style
surface; unsupported output fails with a safe parser error instead of fabricated
empty data.

### Data flow

```text
Broker tool
  → inventory and capability check
  → Observe authorization
  → FortiOSDriver
  → FortiOSSSHTransport
  → credential resolution inside trusted boundary
  → pinned SSH connection
  → fixed FortiOS command
  → known-secret and pattern redaction
  → pure parser
  → vendor-neutral model
  → sanitized CommandResult and secret-free audit event
```

Raw command output is not persisted. Parser errors and transport exceptions use
bounded categories and do not interpolate raw output.

### Passive live test

Run:

```powershell
uv run netsage fortigate live-test
```

Host, port, username, and password are requested interactively. Supplying a
password as a command-line argument or environment variable is intentionally not
supported. The command gathers facts, interfaces, VLANs, ARP, routes, health, and
firewall policy counts over one SSH connection. It does not run ping or
traceroute, change configuration, or persist results.

Verify the displayed host-key fingerprint against a trusted FortiGate console or
another independently trusted channel before accepting it.

### Fixtures

FortiOS parsers and drivers are tested with synthetic files under
`tests/fixtures/fortigate/`. Fixtures use documentation-only address ranges and
locally administered synthetic MAC addresses. A fixture-hygiene test rejects
serial-number fields, undeclared hostnames, globally administered MAC addresses,
and IPv4 addresses outside documentation ranges. Never replace fixtures or inline
tests with production captures.
