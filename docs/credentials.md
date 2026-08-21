# Credential Profiles and OS Keyring

NetSage separates persistent metadata from sensitive runtime material:

```text
CredentialProfile -> serializable metadata and opaque reference
Credential        -> sensitive process-memory runtime value
```

A password profile stores only:

- profile name;
- provider (`keyring`);
- kind (`password`);
- username.

The password is stored through the operating-system credential backend using the
stable keyring service name `NetSage` and the profile name as the key. The
FortiOS driver still depends only on `CredentialProvider.resolve()` and does not
know whether the provider uses Windows Credential Manager, a Linux keyring, or a
future secure backend.

## CLI

```powershell
netsage credentials add
netsage credentials list
netsage credentials show fortigate-readonly
netsage credentials remove fortigate-readonly
netsage credentials rotate fortigate-readonly
```

Add prompts for the password with hidden input and confirmation. Passwords are
never accepted as ordinary CLI flags or environment variables. List and show
read metadata only; show prints `Secret: stored securely` without resolving the
secret. There is no reveal or get-password command.

Rotate replaces only the current OS-keyring value after hidden confirmation. It
does not read the old value for display, change profile metadata, store password
history, or modify the FortiGate password. Device-side password rotation remains
an external administrative action.

Removal is rejected while any Device references the profile. Credential creation
stores the secret first and atomically saves metadata second; if metadata saving
fails, the keyring entry is removed. Removal rolls metadata back if deleting the
keyring entry fails.

If no usable OS keyring backend exists, NetSage fails closed. It never writes a
password into YAML or uses a plaintext fallback. SSH-agent, Vault, cloud secret
managers, API tokens, and environment-based production credentials remain out of
scope.
