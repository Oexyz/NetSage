# Network Drivers

Driver contract maturity: Supported

NetSage drivers translate fixed semantic operations into vendor-specific,
read-only access and normalize the results. AI providers and Broker callers never
receive an SSH session, raw command string, or credential-provider API.

## FortiOS

Implementation maturity: Beta

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
| HA status | `get system ha status` | Read-only |
| SD-WAN members | `diagnose sys sdwan member` | Reviewed read-only semantic request |
| SD-WAN health checks | Trusted Catalog ID | Read-only semantic promotion |
| IPsec Phase 1 | Trusted Catalog ID | Read-only semantic promotion |
| IPsec tunnels / Phase 2 | Trusted Catalog ID | Read-only semantic promotion |
| BGP summary | `get router info bgp summary` | Read-only |
| OSPF process | `get router info ospf status` | Read-only |
| OSPF neighbors | `get router info ospf neighbor all` | Read-only |
| Ping | `execute ping <validated-IP>` | Diagnostic |
| Traceroute | `execute traceroute <validated-IP>` | Diagnostic |

Diagnostics accept only parsed IP address objects and are denied by the default
Observe policy. No user or AI string can become a FortiOS command.

The complete local FortiOS 7.2.13 CLI reference is now transformed into a
generated knowledge catalog with command class, capability, typed argument,
context, execution/parser support, and source line/page metadata. The catalog is
not a transport allowlist and is never exposed as an arbitrary CLI tool. The
fixed operations and three source-traceable semantic Catalog-ID promotions above
are executable only through typed Driver methods. The semantic enum has no
arguments and cannot carry user or AI text. Adding another executable operation
still requires a semantic capability, explicit policy, reviewed typed rendering,
redaction, normalized output or a documented sanitized-text boundary, and tests.

### Semantic observability

The Driver implements twelve additional vendor-neutral operations across HA,
SD-WAN, IPsec, BGP, OSPF, and route summary. Five comprehensive status operations
are AI-promoted; seven focused views remain Broker-only. Comprehensive results
carry explicit collection limits and `truncated`; focused views reject a
truncated source rather than silently discard that state.

The fixed request set intentionally uses `get router info bgp summary` and OSPF
status/neighbor commands rather than the catalogued `diagnose ... show` entries:
the local FortiOS source states that those catalog entries report debugging
status, not routing-neighbor state. See the
[semantic coverage matrix](fortios-semantic-coverage.md).

The HA/SD-WAN/IPsec/BGP/OSPF Capability flags mean that this Driver implements a
safe typed query for the domain. They do not claim that the feature is configured
on a particular appliance. Each status model carries `enabled=true`,
`enabled=false`, or an honest unknown/missing-Evidence outcome based on the
actual response.

Inspect the local catalog without connecting to a device:

```powershell
netsage fortios commands search route
netsage fortios commands show fortios.execute.ping
netsage fortios commands coverage
```

See [FortiOS command catalog](fortios-command-catalog.md) for exact generated
coverage and the distinction between known, executable, and typed output.

### Read-only catalog execution

The expert `FortiOSCatalogExecutor` promotes 515 of 1,049 READ_ONLY definitions
to bounded `SANITIZED_TEXT`; 362 require review and 172 are non-executable. It
accepts only a catalog ID plus validated named arguments. A local dry-run occurs
before runtime preparation, so denied or invalid commands do not verify a host,
resolve a credential, or connect.

Actual execution reuses `FortiOSRuntimeFactory`, the existing host-key trust
manager, credential provider, `FortiOSDriver`, and `FortiOSSSHTransport`. The
transport repeats manifest/disposition/class checks before credential resolution.
It applies existing paging and command timeouts/output limits; the executor adds
double redaction, terminal-control filtering, a tighter result limit, untrusted
result metadata, and secret-free persistent Audit. Text output itself is never
stored or converted into Evidence. See
[FortiOS catalog execution](fortios-catalog-execution.md).

### Shell output handling

FortiOS can paginate long `show` and `get` output at `--More--`. The transport
opens a bounded interactive terminal, waits for the initial prompt, advances each
page with a space, and stops when the device prompt returns. It strips terminal
control and paging artifacts before parsing. NetSage does not run `config system
console` or change the global `output` setting, because that would mutate device
configuration and could affect other administrators.

Parsers accept prompt and command-echo variants, current-VDOM wrappers, omitted
default settings, nested configuration blocks, and common FortiOS appliance model
names. System-health parsing supports both the `Memory states: ... used` format
and the FortiOS 7.2-style total/used/free memory format. The implemented driver is
Beta and deliberately bounded to a FortiOS 7.x-style surface; unsupported output
fails with a safe parser error instead of fabricated empty data.

Domain parsers live under `fortios/semantic/` rather than extending the existing
single parser module indefinitely. They tolerate reordered and extra fields but
reject empty, unrecognized, rejected, or ambiguous output. Explicit disabled or
not-running feature state is modeled; ambiguous empty BGP output remains missing
Evidence. IPsec `key`, `SK_*`, and per-SA key material is redacted before parsing
and is never selected into a normalized model.

The complete passive snapshot and representative HA, disabled SD-WAN, IPsec, and
OSPF semantic paths have been verified against an authorized FortiOS 7.2.13
device. BGP returned ambiguous empty output and correctly became missing
Evidence. No device hostname, address, serial number, credential, peer, interface,
or raw capture from that verification is stored in the repository.

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
