# FortiOS Device Onboarding

The current onboarding workflow supports FortiOS only. A logical Device ID is
the stable handle used by later commands; users no longer need to re-enter the
host, port, username, or password during normal operation.

## First onboarding

```powershell
netsage credentials add
netsage device add
```

Device add performs this fixed sequence:

```text
validate local metadata and credential profile
  -> discover SSH public host key without authentication
  -> display algorithm and SHA-256 fingerprint
  -> require explicit human trust
  -> resolve the keyring credential
  -> authenticate using the reviewed in-memory host key
  -> collect read-only FortiOS facts
  -> persist fingerprint and DeviceRef only after success
```

NetSage does not create users, enable SSH/API access, modify an admin profile, or
change any FortiGate configuration. If authentication or FortiOS verification
fails, no Device or trust record is left behind. Local persistence errors roll
back partial trust state.

## SSH trust

The trust store persists host, port, algorithm, and SHA-256 fingerprint—not a
public-key body. Before every authenticated connection NetSage rediscovers the
current public host key without credentials, compares it with persistent trust,
and passes the newly discovered matching key to AsyncSSH for pinning.

A mismatch aborts before authentication and is never accepted automatically.
The explicit rotation workflow is:

```powershell
netsage device trust-reset DEVICE
```

It displays the old and new identities and requires confirmation before replacing
the fingerprint.

## Device commands

```powershell
netsage devices
netsage device show DEVICE
netsage device test DEVICE
netsage device remove DEVICE
netsage investigate DEVICE
```

List and show read only local metadata and perform no network or keyring access.
Device test reports configured, reachable, host-key, credential, authentication,
FortiOS, and facts stages. An offline device remains in Inventory. Remove deletes
the Device and its trust record after confirmation but retains a potentially
shared credential profile.

Stored investigation reuses the existing FortiOS transport, Tool Broker,
in-memory Audit, Evidence Collector, deterministic investigator, and report
renderer. Evidence, Audit, reports, and Investigation history remain in-memory
and are not added to local YAML state.

FortiOS support remains experimental. Live verification against one authorized
device does not establish universal FortiOS compatibility.

The complete `setup -> credentials add -> device add -> device test -> investigate`
workflow has been live-verified against an authorized FortiOS 7.2.13 device. No
credential, raw output, Evidence, Audit event, or Investigation record was written
to NetSage YAML state or the repository.
