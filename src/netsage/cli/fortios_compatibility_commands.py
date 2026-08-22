"""FortiOS compatibility probe CLI and anonymized export rendering."""

import asyncio
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from netsage.compatibility import (
    CompatibilityExportError,
    FortiOSCompatibilityReport,
    FortiOSCompatibilityService,
    export_compatibility_report,
)
from netsage.credentials import KeyringSecretStore
from netsage.history import HistoryError
from netsage.inventory import UnknownDeviceError
from netsage.state import InvalidStateReferenceError, LocalState, StateError

console = Console()


def _state() -> LocalState:
    state = LocalState()
    state.initialize()
    return state


def register_compatibility_command(app: typer.Typer) -> None:
    app.command("compatibility")(compatibility_command)


def compatibility_command(
    device_id: str,
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit an anonymized typed JSON report."),
    ] = False,
    export: Annotated[
        Path | None,
        typer.Option(
            "--export",
            help="Atomically write an anonymized JSON report.",
        ),
    ] = None,
    force: Annotated[
        bool,
        typer.Option("--force", help="Replace an existing regular export file."),
    ] = False,
) -> None:
    """Characterize core semantic compatibility without raw CLI or network data."""

    try:
        state = _state()
        report = asyncio.run(
            FortiOSCompatibilityService(
                state=state,
                secrets=KeyringSecretStore(),
            ).inspect(device_id)
        )
        exported = (
            export_compatibility_report(report, export, force=force) if export is not None else None
        )
    except (
        CompatibilityExportError,
        HistoryError,
        InvalidStateReferenceError,
        StateError,
        UnknownDeviceError,
        ValueError,
    ) as error:
        console.print(f"[red]Compatibility probe failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    if json_output:
        console.print_json(report.anonymized_copy().model_dump_json())
        return
    _print_report(report)
    if exported is not None:
        console.print(f"Anonymized compatibility report exported: {exported}")


def _print_report(report: FortiOSCompatibilityReport) -> None:
    summary = Table(title="FortiOS Compatibility Report")
    summary.add_column("Field")
    summary.add_column("Value")
    summary.add_row("Device", report.device_id)
    summary.add_row("Firmware", report.firmware.display if report.firmware else "UNKNOWN")
    summary.add_row(
        "Build",
        str(report.firmware.build) if report.firmware and report.firmware.build else "-",
    )
    summary.add_row("Model family", report.model_family or "UNKNOWN")
    summary.add_row("VDOM mode", report.vdom.mode.value)
    summary.add_row("VDOM context", report.vdom.context.value)
    summary.add_row("Fingerprint", report.fingerprint)
    console.print(summary)

    matrix = Table(title="Semantic compatibility")
    matrix.add_column("Area")
    matrix.add_column("State")
    matrix.add_column("Parser")
    matrix.add_column("Error")
    matrix.add_column("Variants")
    for result in report.areas:
        matrix.add_row(
            result.area.value,
            result.state.value.upper(),
            result.parser_state.value,
            result.error_category.value,
            ", ".join(result.parser_variants) or "-",
        )
    console.print(matrix)
    console.print("No configuration changes were made. No raw CLI was stored.")
    console.print("JSON and file exports are anonymized by default.")
