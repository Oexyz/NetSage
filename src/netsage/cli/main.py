"""NetSage command-line entry point."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netsage import __version__
from netsage.distribution import install_current_executable, uninstall_current_executable
from netsage.distribution.windows import DistributionInstallError

app = typer.Typer(
    name="netsage",
    help="Open-source AI Network & Infrastructure Investigator",
    no_args_is_help=True,
    invoke_without_command=True,
)
console = Console()


def version_callback(value: bool) -> None:
    """Print the version and exit."""
    if value:
        console.print(f"NetSage {__version__}")
        raise typer.Exit()


@app.callback()
def main(
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
    except (ImportError, RuntimeError):
        pass
    return "UNAVAILABLE", "no usable OS keyring backend"


def _docker_status() -> tuple[str, str]:
    status, details = _command_status("docker")
    if status == "OK":
        return status, details
    desktop_cli = Path("C:/Program Files/Docker/Docker/resources/bin/docker.exe")
    if desktop_cli.is_file():
        return "OK", f"{desktop_cli} (available after terminal restart)"
    return "OPTIONAL", details


@app.command()
def doctor() -> None:
    """Check local runtime and optional development services."""
    checks = [
        ("Python", "OK" if sys.version_info >= (3, 13) else "UNSUPPORTED", sys.version.split()[0]),
        ("Git", *_command_status("git")),
        ("SSH", *_command_status("ssh")),
        ("Credential Store", *_credential_store_status()),
        ("Docker (optional)", *_docker_status()),
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
    """Show guidance for future local setup workflows."""
    console.print("Interactive setup is planned; no credentials were changed.")


@app.command()
def device() -> None:
    """Placeholder for read-only single-device inspection."""
    console.print("Device inspection is not implemented yet.")


@app.command()
def devices() -> None:
    """Placeholder for inventory listing."""
    console.print("Inventory listing is not implemented yet.")


if __name__ == "__main__":
    app()
