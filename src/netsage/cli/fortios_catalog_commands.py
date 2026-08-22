"""FortiOS catalog inspection and policy-controlled expert read execution."""

import asyncio
from typing import Annotated, cast

import typer
from pydantic import JsonValue
from rich.console import Console
from rich.table import Table

from netsage.cli.fortios_compatibility_commands import register_compatibility_command
from netsage.credentials import CredentialStoreError, KeyringSecretStore
from netsage.drivers.fortios import FortiOSTransportError
from netsage.drivers.fortios.catalog import (
    FortiOSCatalogDryRun,
    FortiOSCatalogError,
    FortiOSCatalogExecutionError,
    FortiOSCatalogExecutor,
    FortiOSCommandDefinition,
    FortiOSCommandRegistry,
    UnknownFortiOSCommandError,
)
from netsage.history import HistoryError, SQLiteAuditSink
from netsage.inventory import UnknownDeviceError
from netsage.models import Platform
from netsage.onboarding import FortiOSRuntimeFactory
from netsage.security import SecretRedactor
from netsage.state import (
    InvalidStateReferenceError,
    LocalState,
    SSHHostTrustManager,
    SSHTrustError,
    StateError,
)

console = Console()
fortios_app = typer.Typer(
    name="fortios",
    help="Inspect FortiOS catalog metadata and run bounded semantic compatibility checks.",
    no_args_is_help=True,
)
commands_app = typer.Typer(
    name="commands",
    help="Search command definitions, inspect source metadata, and show coverage.",
    no_args_is_help=True,
)
fortios_app.add_typer(commands_app)
register_compatibility_command(fortios_app)


def _registry() -> FortiOSCommandRegistry:
    return FortiOSCommandRegistry()


def _state() -> LocalState:
    state = LocalState()
    state.initialize()
    return state


def _fail(message: str, error: Exception) -> typer.Exit:
    console.print(f"[red]{message}[/red]")
    return typer.Exit(code=1)


@commands_app.command("search")
def search_commands(
    query: str,
    limit: int = typer.Option(50, min=1, max=1000, help="Maximum result count."),
) -> None:
    """Search local command IDs, paths, syntax, scopes, and capabilities."""

    try:
        matches = _registry().search(query, limit=limit)
    except (FortiOSCatalogError, ValueError) as error:
        raise _fail("FortiOS command search failed.", error) from error
    table = Table(title=f"FortiOS commands matching: {query}")
    table.add_column("Command ID")
    table.add_column("Path")
    table.add_column("Class")
    table.add_column("Support")
    for definition in matches:
        table.add_row(
            definition.id,
            _display_path(definition),
            definition.command_class.value,
            definition.execution_support.value,
        )
    console.print(table)
    console.print(f"Results: {len(matches)} (local catalog only; no device connection)")


@commands_app.command("show")
def show_command(command_id: str) -> None:
    """Show one known definition and its policy/source metadata without executing it."""

    try:
        definition = _registry().get(command_id)
    except UnknownFortiOSCommandError as error:
        raise _fail("Unknown FortiOS command ID.", error) from error
    except FortiOSCatalogError as error:
        raise _fail("FortiOS command catalog is unavailable.", error) from error
    table = Table(title="FortiOS command definition")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("ID", definition.id)
    table.add_row("Path", _display_path(definition))
    table.add_row("Syntax", definition.syntax)
    table.add_row("Classification", definition.command_class.value)
    table.add_row("Capability", definition.capability.value if definition.capability else "-")
    table.add_row("Context", definition.context.value)
    table.add_row("Known", "yes")
    table.add_row("Observe policy allows class", "yes" if definition.observe_allowed else "no")
    table.add_row(
        "Executable in default Observe",
        "yes" if definition.executable_in_observe else "no",
    )
    table.add_row("Execution support", definition.execution_support.value)
    table.add_row("Execution disposition", definition.execution_disposition.value)
    table.add_row("Execution reason", definition.execution_reason.value)
    table.add_row("Parser support", definition.parser_support.value)
    table.add_row("Safely renderable", "yes" if definition.renderable else "no")
    table.add_row("AI-visible", "no")
    table.add_row(
        "Required arguments",
        ", ".join(argument.name for argument in definition.arguments if argument.required) or "-",
    )
    table.add_row(
        "Optional arguments",
        ", ".join(argument.name for argument in definition.arguments if not argument.required)
        or "-",
    )
    table.add_row(
        "Source",
        f"{definition.source.document}:{definition.source.line}"
        + (f" (reference page {definition.source.page})" if definition.source.page else ""),
    )
    console.print(table)
    if definition.arguments:
        argument_table = Table(title="Typed arguments")
        argument_table.add_column("Name")
        argument_table.add_column("Kind")
        argument_table.add_column("Required")
        argument_table.add_column("Choices")
        argument_table.add_column("Sensitive")
        for argument in definition.arguments:
            argument_table.add_row(
                argument.name,
                argument.kind.value,
                "yes" if argument.required else "no",
                ", ".join(argument.choices) or "-",
                "yes" if argument.sensitive else "no",
            )
        console.print(argument_table)
    console.print("No command was executed.")


@commands_app.command("coverage")
def show_coverage() -> None:
    """Show source-derived catalog, class, execution, and parser counts."""

    try:
        manifest = _registry().manifest
    except FortiOSCatalogError as error:
        raise _fail("FortiOS command catalog is unavailable.", error) from error
    coverage = manifest.coverage
    table = Table(title=f"FortiOS {manifest.fortios_version} CLI reference coverage")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    rows = (
        ("Source topic commands", coverage.source_topic_commands),
        ("Source additional syntax commands", coverage.source_syntax_commands),
        ("Source configuration-context commands", coverage.source_context_commands),
        ("Source conversion/non-command artifacts", coverage.source_non_command_artifacts),
        ("Commands discovered", coverage.commands_discovered),
        ("Commands catalogued", coverage.commands_catalogued),
        ("Source definitions uncatalogued", coverage.source_definitions_uncatalogued),
        ("Read-only", coverage.read_only),
        ("Diagnostic", coverage.diagnostic),
        ("Configuration", coverage.configuration),
        ("Destructive", coverage.destructive),
        ("Structured executable", coverage.structured_executable),
        ("Executable in default Observe", coverage.executable_in_observe),
        ("READ_ONLY safely executable", coverage.read_only_executable),
        ("READ_ONLY requires review", coverage.read_only_requires_review),
        ("READ_ONLY non-executable", coverage.read_only_non_executable),
        ("DIAGNOSTIC structured semantic operations", coverage.diagnostic_structured),
        ("DIAGNOSTIC denied by default", coverage.diagnostic_default_denied),
        ("CONFIGURATION executable", coverage.configuration_executable),
        ("DESTRUCTIVE executable", coverage.destructive_executable),
        ("Typed output parsers", coverage.typed_parsers),
        ("Sanitized-text parsers", coverage.sanitized_text_parsers),
        ("Catalog-only", coverage.catalog_only),
    )
    for label, count in rows:
        table.add_row(label, str(count))
    console.print(table)
    console.print("Catalog coverage: 100% of source definitions discovered by the generator.")
    console.print("This does not mean 100% executable or typed FortiOS support.")


@fortios_app.command("run")
def run_catalog_command(
    device_id: str,
    command_id: str,
    argument: Annotated[
        list[str] | None,
        typer.Option(
            "--arg",
            help="Named argument as NAME=VALUE; repeat for multiple values.",
        ),
    ] = None,
    dry_run: Annotated[
        bool,
        typer.Option(
            "--dry-run",
            help="Validate policy and rendering without credentials or device access.",
        ),
    ] = False,
    json_output: Annotated[
        bool,
        typer.Option(
            "--json",
            help="Emit secret-free structured JSON metadata and sanitized output.",
        ),
    ] = False,
) -> None:
    """Run one promoted READ_ONLY catalog ID through the existing trusted runtime."""

    try:
        arguments = _parse_named_arguments(argument or [])
    except ValueError as error:
        console.print("[red]INVALID_ARGUMENT:[/red] Catalog arguments must use NAME=VALUE.")
        raise typer.Exit(code=1) from error
    try:
        state = _state()
        inventory = state.load_inventory()
        device = inventory.get_device(device_id)
        if device.platform is not Platform.FORTIOS:
            raise ValueError("Catalog execution requires a FortiOS device")
        registry = _registry()
        preflight = FortiOSCatalogExecutor(
            device_id=device.name,
            registry=registry,
            redactor=SecretRedactor(),
        )
        plan = preflight.dry_run(command_id, arguments)
        if dry_run:
            _print_dry_run(plan, json_output=json_output)
            return
        runtime = FortiOSRuntimeFactory(
            profiles=state.credentials,
            secrets=KeyringSecretStore(),
            trust=SSHHostTrustManager(state.host_trust),
        )
        prepared = asyncio.run(runtime.prepare(device))
        executor = FortiOSCatalogExecutor(
            device_id=device.name,
            transport=prepared.driver,
            registry=registry,
            redactor=prepared.redactor,
            audit_sink=SQLiteAuditSink(state.history, redactor=prepared.redactor),
        )
        result = asyncio.run(executor.execute(command_id, arguments))
    except FortiOSCatalogExecutionError as error:
        console.print(f"[red]{error.code.value}:[/red] {error}")
        raise typer.Exit(code=1) from error
    except (
        CredentialStoreError,
        FortiOSTransportError,
        HistoryError,
        InvalidStateReferenceError,
        SSHTrustError,
        StateError,
        UnknownDeviceError,
        ValueError,
    ) as error:
        console.print("[red]TRANSPORT_FAILED:[/red] FortiOS catalog preparation failed.")
        raise typer.Exit(code=1) from error
    if json_output:
        console.print_json(result.model_dump_json())
        return
    table = Table(title="FortiOS catalog execution")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Device", result.device_id)
    table.add_row("Command ID", result.command_id)
    table.add_row("Classification", result.classification.value)
    table.add_row("Output type", result.output_type.value)
    table.add_row("Trust", result.trust.value)
    table.add_row("Persisted", "no")
    table.add_row("Evidence created", "no")
    console.print(table)
    console.print(result.sanitized_output, markup=False, highlight=False)
    console.print("No configuration changes were made. Output was not persisted.")


def _parse_named_arguments(values: list[str]) -> dict[str, JsonValue]:
    arguments: dict[str, JsonValue] = {}
    for item in values:
        if "=" not in item:
            raise ValueError("Catalog arguments must use NAME=VALUE")
        name, value = item.split("=", 1)
        if not name or name in arguments:
            raise ValueError("Catalog argument names must be unique and non-empty")
        arguments[name] = cast(JsonValue, value)
    return arguments


def _print_dry_run(plan: FortiOSCatalogDryRun, *, json_output: bool) -> None:
    if json_output:
        console.print_json(plan.model_dump_json())
        return
    table = Table(title="FortiOS catalog dry run")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Device", plan.device_id)
    table.add_row("Command ID", plan.command_id)
    table.add_row("Classification", plan.classification.value)
    table.add_row("Policy", "allowed" if plan.authorization.allowed else "denied")
    table.add_row("Rendered command", plan.rendered_command)
    table.add_row("Output type", plan.output_type.value)
    table.add_row("AI-visible", "no")
    console.print(table)
    console.print("Dry run only. No credentials were resolved and no device was contacted.")


def _display_path(definition: FortiOSCommandDefinition) -> str:
    return f"{definition.scope} > {definition.path}" if definition.scope else definition.path
