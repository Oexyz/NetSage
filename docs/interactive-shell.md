# Interactive Shell

Running NetSage without a subcommand starts an interactive NetSage command loop:

```text
netsage

netsage> devices
netsage> investigate firewall-example
netsage> ask firewall-example "Check routing."
netsage> fortios run firewall-example fortios.execute.cpu.show --dry-run
netsage> exit
```

The existing one-shot CLI remains unchanged:

```powershell
netsage devices
netsage investigate firewall-example
netsage ask firewall-example "Check routing."
netsage fortios run firewall-example fortios.execute.cpu.show --dry-run
```

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
hidden prompts and are never accepted as shell command arguments.

## Security boundary

This is a NetSage command loop, not an operating-system shell. The first token
must be a registered top-level NetSage command. Inputs such as `whoami`, `dir`,
`ls`, `rm`, `cmd`, `powershell`, or `bash` are reported as unknown commands. They
are never forwarded to `os.system`, `subprocess`, `shell=True`, or another
executable.

Startup reads only enough local metadata to show a device count and checks
whether `codex` is present on `PATH`. It does not connect to devices, resolve
credentials, start AI, parse `fortios.md`, or scan a network. Network access
begins only when an explicitly selected existing command requires it.

Promoted read-only catalog commands are available through the registered
`fortios run` handler. The REPL still receives only Device ID, Catalog ID, and
named arguments; it never interprets FortiOS syntax entered at the root prompt.
