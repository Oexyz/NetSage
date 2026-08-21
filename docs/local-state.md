# Secure Local State

NetSage stores application configuration at a platform-appropriate user-level
path:

- Windows: `%LOCALAPPDATA%\NetSage\`
- Linux: `$XDG_CONFIG_HOME/netsage/` or `~/.config/netsage/`
- macOS: `~/Library/Application Support/NetSage/`

The directory contains four logically separate YAML documents and one History
database:

```text
config.yaml          application settings
inventory.yaml       non-secret DeviceRef inventory
credentials.yaml     credential profile metadata only
known-hosts.yaml     SSH host identity fingerprints
history.sqlite3      sanitized Investigation, Evidence, and Audit history
```

Every document has `schema_version: 1`. Unknown future versions, malformed YAML,
invalid models, and broken cross-references fail clearly. Existing invalid files
are never overwritten or silently repaired.

## Atomic writes and permissions

Each write uses a restrictive same-directory temporary file, flushes and fsyncs
its contents, atomically replaces the destination, and fsyncs the containing
directory where supported. A failed replace leaves the previous state file
unchanged and removes the temporary file.

On POSIX systems NetSage creates the state directory with mode `0700` and files
with mode `0600`. Windows state remains under the current user's Local AppData
ACL; NetSage does not apply fragile POSIX permission assumptions on Windows.

## Allowed persistent data

- logical device IDs, platform, host, port, sites, groups, tags, and capabilities;
- opaque credential references;
- credential provider, kind, and username metadata;
- SSH host, port, public-key algorithm, and SHA-256 fingerprint.

YAML state and SQLite History never contain passwords, API tokens, private key content, SNMP
communities, AAA secrets, authorization headers, raw Credential objects, raw
device output, or raw authentication material. SQLite may contain normalized
operational Evidence, Reports, and safe Audit metadata.

`netsage setup` initializes missing state documents and validates existing ones.
Other state-aware commands initialize missing files lazily with the same policy.
