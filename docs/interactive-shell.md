# Interactive Shell

Maturity: Supported

Running NetSage without a subcommand starts an interactive NetSage command loop:

```text
netsage

netsage> devices
netsage> investigate firewall-example
netsage> ai codex login
netsage> ai codex status
netsage> ask firewall-example "Check routing."
netsage> fortios run firewall-example fortios.execute.cpu.show --dry-run
netsage> exit
```

The existing one-shot CLI remains unchanged:

```powershell
netsage devices
netsage investigate firewall-example
netsage ai codex login
netsage ai codex status
netsage ask firewall-example "Check routing."
netsage fortios run firewall-example fortios.execute.cpu.show --dry-run
```

Feature-focused deterministic investigations use the same handler in both
forms:

```text
netsage investigate firewall-example --focus ha
netsage> investigate firewall-example --focus ha
```

Valid focuses are `health`, `ha`, `sdwan`, `ipsec`, and `routing`.

## Shared command implementation

The shell tokenizes a line with `shlex` and invokes the same root Typer command
tree used by one-shot calls. It has no duplicate device, credential,
investigation, AI, or catalog handlers. Nested commands, options, validation,
hidden prompts, and exit codes therefore retain the existing application
behavior.

Within the shell:

- `help` shows root help;
- `help device`, `help ai`, or `help fortios` shows nested Typer help;
- `exit` and `quit` leave the shell;
- EOF/Ctrl+D exits cleanly;
- Ctrl+C at the prompt cancels only the current input;
- Ctrl+C during a command is reported as command cancellation.

No command history is persisted. Passwords and provider API keys continue to use
hidden prompts and are never accepted as shell command arguments. Native Codex
OAuth prints only the temporary device URL/code; access and refresh tokens are
never printed or added to command history.

## Security boundary

This is a NetSage command loop, not an operating-system shell. The first token
must be a registered top-level NetSage command. Inputs such as `whoami`, `dir`,
`ls`, `rm`, `cmd`, `powershell`, or `bash` are reported as unknown commands. They
are never forwarded to `os.system`, `subprocess`, `shell=True`, or another
executable.

Startup reads only enough local metadata to show a device count and configured
AI selection. It does not check authentication, connect to devices, resolve
credentials, start AI, parse `fortios.md`, or scan a network. Network access
begins only when an explicitly selected existing command requires it.

Promoted read-only catalog commands are available through the registered
`fortios run` handler. The REPL still receives only Device ID, Catalog ID, and
named arguments; it never interprets FortiOS syntax entered at the root prompt.
