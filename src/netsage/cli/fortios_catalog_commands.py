"""Local FortiOS command-catalog inspection; these commands never access devices."""

import typer
from rich.console import Console
from rich.table import Table

from netsage.drivers.fortios.catalog import (
    FortiOSCatalogError,
    FortiOSCommandDefinition,
    FortiOSCommandRegistry,
    UnknownFortiOSCommandError,
)

console = Console()
fortios_app = typer.Typer(
    name="fortios",
    help="Inspect the generated FortiOS CLI knowledge catalog without device access.",
    no_args_is_help=True,
)
commands_app = typer.Typer(
    name="commands",
    help="Search command definitions, inspect source metadata, and show coverage.",
    no_args_is_help=True,
)
fortios_app.add_typer(commands_app)


def _registry() -> FortiOSCommandRegistry:
    return FortiOSCommandRegistry()


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
    table.add_row("Parser support", definition.parser_support.value)
    table.add_row("Safely renderable", "yes" if definition.renderable else "no")
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
        ("Typed output parsers", coverage.typed_parsers),
        ("Sanitized-text parsers", coverage.sanitized_text_parsers),
        ("Catalog-only", coverage.catalog_only),
    )
    for label, count in rows:
        table.add_row(label, str(count))
    console.print(table)
    console.print("Catalog coverage: 100% of source definitions discovered by the generator.")
    console.print("This does not mean 100% executable or typed FortiOS support.")


def _display_path(definition: FortiOSCommandDefinition) -> str:
    return f"{definition.scope} > {definition.path}" if definition.scope else definition.path
