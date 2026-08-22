"""NetSage command-line entry point."""

from __future__ import annotations

import asyncio
import shutil
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from netsage import __version__
from netsage.broker import ToolBroker
from netsage.cli.ai_commands import ai_app, ai_doctor_checks, ask_device
from netsage.cli.fortios_catalog_commands import fortios_app
from netsage.cli.shell import run_interactive_shell
from netsage.cli.state_commands import (
    credentials_app,
    device_app,
    investigate_device,
    investigation_app,
    list_audit,
    list_devices,
    list_investigations,
    setup_state,
)
from netsage.credentials import (
    Credential,
    CredentialKind,
    EphemeralCredentialProvider,
)
from netsage.distribution import install_current_executable, uninstall_current_executable
from netsage.distribution.windows import DistributionInstallError
from netsage.drivers.fortios import (
    FORTIOS_CAPABILITIES,
    FortiOSDriver,
    FortiOSParseError,
    FortiOSSnapshot,
    FortiOSSSHTransport,
    FortiOSTransportError,
    SSHHostKeyPin,
    discover_ssh_host_key,
)
from netsage.evidence import EvidenceCollector, EvidenceFactory, InMemoryEvidenceStore
from netsage.history import HISTORY_SCHEMA_VERSION, HistoryDatabase, HistoryError
from netsage.inventory import Inventory
from netsage.investigations import (
    FortiOSInvestigationFocus,
    FortiOSInvestigator,
    InvestigationReport,
    render_investigation_report,
)
from netsage.models import CredentialReference, DeviceRef, Platform
from netsage.security import SecretRedactor
from netsage.state import StatePaths
from netsage.tools import FortiOSToolSet

app = typer.Typer(
    name="netsage",
    help="Open-source AI Network & Infrastructure Investigator",
    no_args_is_help=False,
    invoke_without_command=True,
)
console = Console()
fortigate_app = typer.Typer(
    name="fortigate",
    help="Read-only FortiGate inspection and diagnostics.",
    no_args_is_help=True,
)
app.add_typer(fortigate_app)
app.add_typer(credentials_app)
app.add_typer(device_app)
app.add_typer(investigation_app)
app.add_typer(ai_app)
app.add_typer(fortios_app)


def version_callback(value: bool) -> None:
    """Print the version and exit."""
    if value:
        console.print(f"NetSage {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    ctx: typer.Context,
    version: bool = typer.Option(
        False,
        "--version",
        callback=version_callback,
        is_eager=True,
        help="Show the NetSage version and exit.",
    ),
    install: bool = typer.Option(
        False,
        "-install",
        is_eager=True,
        help="Install the standalone Windows executable for the current user.",
    ),
) -> None:
    """Safely investigate networks using structured, read-only tools."""
    if install:
        _run_install_path()
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        run_interactive_shell(app)


def _run_install_path() -> None:
    try:
        result = install_current_executable()
    except DistributionInstallError as error:
        console.print(f"[red]Installation failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    action = "Added installation directory to PATH." if result.path_changed else "PATH unchanged."
    console.print(f"Installed NetSage to {result.executable}")
    console.print(action)
    console.print("Open a new terminal, then run: netsage doctor")


def _run_uninstall_path() -> None:
    try:
        result = uninstall_current_executable()
    except DistributionInstallError as error:
        console.print(f"[red]Uninstall failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    console.print("Removed the NetSage installation directory from the user PATH.")
    if result.executable_removed:
        console.print(f"Removed {result.executable}")
    elif result.executable.exists():
        console.print(
            f"The running executable remains at {result.executable}; delete it after exiting."
        )


def _command_status(command: str) -> tuple[str, str]:
    path = shutil.which(command)
    return ("OK", path) if path else ("MISSING", "not found on PATH")


def _credential_store_status() -> tuple[str, str]:
    try:
        import keyring

        backend = keyring.get_keyring()
        if backend.priority > 0:
            return "OK", backend.name
    except Exception:
        return "UNAVAILABLE", "no usable OS keyring backend"
    return "UNAVAILABLE", "no usable OS keyring backend"


def _docker_status() -> tuple[str, str]:
    status, details = _command_status("docker")
    if status == "OK":
        return status, details
    desktop_cli = Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")
    if desktop_cli.is_file():
        return "OK", f"{desktop_cli} (available after terminal restart)"
    return "OPTIONAL", details


def _history_status() -> tuple[str, str]:
    path = StatePaths.default().history
    if not path.exists():
        return "MISSING", "run netsage setup"
    try:
        HistoryDatabase(path).quick_check()
    except HistoryError as error:
        return "ERROR", str(error)
    return "OK", f"schema {HISTORY_SCHEMA_VERSION}; quick_check ok"


@app.command()
def doctor() -> None:
    """Check local runtime and optional development services."""
    checks = [
        ("Python", "OK" if sys.version_info >= (3, 13) else "UNSUPPORTED", sys.version.split()[0]),
        ("Git", *_command_status("git")),
        ("SSH", *_command_status("ssh")),
        ("Credential Store", *_credential_store_status()),
        ("History Database", *_history_status()),
        ("Docker (optional)", *_docker_status()),
        *ai_doctor_checks(),
    ]
    table = Table(title="NetSage development environment")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Details")
    for component, status, details in checks:
        style = "green" if status == "OK" else "yellow"
        table.add_row(component, f"[{style}]{status}[/{style}]", details)
    console.print(table)


@app.command("install-path")
def install_path() -> None:
    """Install the standalone Windows executable for the current user."""
    _run_install_path()


@app.command("uninstall-path")
def uninstall_path() -> None:
    """Remove the per-user Windows installation and PATH entry."""
    _run_uninstall_path()


@app.command()
def setup() -> None:
    """Initialize secure, versioned, non-secret local state."""
    setup_state()


@app.command()
def devices() -> None:
    """List persistent device metadata without connecting."""
    list_devices()


@app.command()
def investigate(
    device_id: str,
    ephemeral: bool = typer.Option(
        False,
        "--ephemeral",
        help="Do not persist Investigation, Evidence, or Audit history.",
    ),
    focus: Annotated[
        FortiOSInvestigationFocus,
        typer.Option(
            "--focus",
            help="Collect only the selected deterministic semantic domain.",
        ),
    ] = FortiOSInvestigationFocus.HEALTH,
) -> None:
    """Run a deterministic investigation for a stored logical Device ID."""
    investigate_device(device_id, ephemeral=ephemeral, focus=focus)


@app.command()
def investigations(limit: int = typer.Option(50, min=1, max=1000)) -> None:
    """List persistent local investigation history without connecting."""
    list_investigations(limit)


@app.command()
def audit(limit: int = typer.Option(50, min=1, max=1000)) -> None:
    """List recent append-only persistent audit events."""
    list_audit(limit)


@app.command()
def ask(device_id: str, question: str) -> None:
    """Ask the selected AI provider to reason over sanitized Evidence."""

    ask_device(device_id, question)


@fortigate_app.command("live-test")
def fortigate_live_test() -> None:
    """Run a passive FortiGate snapshot with an in-memory password only."""

    host, port, username, password, pin = _prompt_fortigate_access()
    try:
        snapshot = asyncio.run(_collect_fortigate_snapshot(host, port, username, password, pin))
    except (FortiOSTransportError, FortiOSParseError, ValueError) as error:
        console.print(f"[red]FortiGate read-only test failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    finally:
        password = ""  # Minimize the lifetime of the local reference; Python cannot zero strings.
    _print_fortigate_snapshot(snapshot)


@fortigate_app.command("investigate")
def fortigate_investigate() -> None:
    """Run an evidence-backed deterministic FortiGate health investigation."""

    host, port, username, password, pin = _prompt_fortigate_access()
    try:
        report = asyncio.run(
            _collect_fortigate_health_investigation(host, port, username, password, pin)
        )
    except (FortiOSTransportError, FortiOSParseError, ValueError) as error:
        console.print(f"[red]FortiGate investigation failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    finally:
        password = ""  # Minimize the lifetime of the local reference; Python cannot zero strings.
    console.print(render_investigation_report(report))


def _prompt_fortigate_access() -> tuple[str, int, str, str, SSHHostKeyPin]:
    host = typer.prompt("FortiGate host")
    port = typer.prompt("SSH port", default=22, type=int)
    try:
        pin = asyncio.run(discover_ssh_host_key(host, port))
    except FortiOSTransportError as error:
        console.print(f"[red]Host-key discovery failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    console.print(f"SSH host key: {pin.algorithm} {pin.fingerprint}")
    if not typer.confirm("Trust this host key for this process only?", default=False):
        console.print("Aborted before credentials were requested.")
        raise typer.Exit(code=1)

    username = typer.prompt("Username")
    password = typer.prompt("Password", hide_input=True)
    console.print("Credential persistence: disabled (process memory only).")
    return host, port, username, password, pin


async def _collect_fortigate_snapshot(
    host: str,
    port: int,
    username: str,
    password: str,
    pin: SSHHostKeyPin,
) -> FortiOSSnapshot:
    _device, driver = _build_fortigate_driver(host, port, username, password, pin)
    return await driver.get_snapshot()


def _build_fortigate_driver(
    host: str,
    port: int,
    username: str,
    password: str,
    pin: SSHHostKeyPin,
) -> tuple[DeviceRef, FortiOSDriver]:
    credential_ref = "ephemeral-fortigate-live"
    device = DeviceRef(
        name="fortigate-live",
        host=host,
        port=port,
        platform=Platform.FORTIOS,
        credential_ref=CredentialReference(credential_ref),
        capabilities=FORTIOS_CAPABILITIES,
    )
    provider = EphemeralCredentialProvider(
        credential_ref,
        Credential(username=username, secret=password, kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(
        device,
        provider,
        known_hosts_data=pin.known_hosts_data,
    )
    return device, FortiOSDriver(device.name, transport)


async def _collect_fortigate_health_investigation(
    host: str,
    port: int,
    username: str,
    password: str,
    pin: SSHHostKeyPin,
) -> InvestigationReport:
    device, driver = _build_fortigate_driver(host, port, username, password, pin)
    inventory = Inventory(devices={device.name: device})
    redactor = SecretRedactor(known_secrets=(password,))
    broker = ToolBroker(
        inventory=inventory,
        redactor=redactor,
        user="local-cli",
        ai_provider=None,
    )
    FortiOSToolSet({device.name: driver}).register(broker)
    store = InMemoryEvidenceStore(redactor=redactor)
    collector = EvidenceCollector(
        broker=broker,
        inventory=inventory,
        factory=EvidenceFactory(redactor=redactor),
        store=store,
        driver="FortiOSDriver",
    )
    investigator = FortiOSInvestigator(collector=collector, redactor=redactor)
    return await investigator.investigate_health(device.name)


def _print_fortigate_snapshot(snapshot: FortiOSSnapshot) -> None:
    table = Table(title="FortiGate read-only snapshot")
    table.add_column("Area")
    table.add_column("Result")
    table.add_row("Model", snapshot.facts.model)
    table.add_row("FortiOS", snapshot.facts.os_version)
    table.add_row("Interfaces", str(len(snapshot.interfaces)))
    table.add_row("VLANs", str(len(snapshot.vlans)))
    table.add_row("ARP entries", str(len(snapshot.arp_entries)))
    table.add_row("Routes", str(len(snapshot.routes)))
    table.add_row("Firewall policies", str(len(snapshot.firewall_policies)))
    table.add_row("Health", snapshot.health.status.value)
    console.print(table)
    console.print("No configuration changes were made.")


if __name__ == "__main__":
    app()
