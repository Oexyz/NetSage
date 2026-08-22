"""Interactive NetSage-only command loop over the existing Typer application."""

from __future__ import annotations

import shlex
from collections.abc import Callable, Sequence

import typer
from rich.console import Console
from typer._click.exceptions import ClickException, Exit
from typer.main import get_command

from netsage import __version__
from netsage.inventory.store import InventoryStore
from netsage.state import ApplicationSettingsStore, StateError, StatePaths

InputReader = Callable[[str], str]


class NetSageInteractiveShell:
    """Dispatch only registered NetSage commands; unknown input never reaches an OS shell."""

    def __init__(
        self,
        application: typer.Typer,
        *,
        input_reader: InputReader = input,
        console: Console | None = None,
    ) -> None:
        self._command = get_command(application)
        self._input = input_reader
        self._console = console or Console()

    def run(self) -> None:
        self._print_banner()
        while True:
            try:
                raw = self._input("netsage> ")
            except EOFError:
                self._console.print()
                return
            except KeyboardInterrupt:
                self._console.print("\nInput cancelled. Type 'exit' to leave NetSage.")
                continue
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                tokens = shlex.split(stripped, posix=True)
            except ValueError:
                self._console.print("Invalid command syntax. Check quoting and try again.")
                continue
            if not tokens:
                continue
            if tokens[0].casefold() in {"exit", "quit"} and len(tokens) == 1:
                return
            if tokens[0].casefold() == "help":
                self._invoke([*tokens[1:], "--help"] if len(tokens) > 1 else ["--help"])
                continue
            if not self._known_top_level(tokens[0]):
                self._console.print(f"Unknown command: {tokens[0]}")
                self._console.print("Type 'help' to list available commands.")
                continue
            try:
                self._invoke(tokens)
            except KeyboardInterrupt:
                self._console.print("\nCommand cancelled.")

    def _invoke(self, arguments: Sequence[str]) -> None:
        try:
            self._command.main(
                args=list(arguments),
                prog_name="netsage",
                standalone_mode=False,
            )
        except ClickException as error:
            error.show()
        except Exit:
            return

    def _known_top_level(self, name: str) -> bool:
        commands = getattr(self._command, "commands", {})
        return isinstance(commands, dict) and name in commands

    def _print_banner(self) -> None:
        paths = StatePaths.default()
        device_count: str
        if paths.inventory.is_file():
            try:
                device_count = str(len(InventoryStore(paths.inventory).load().devices))
            except (OSError, StateError):
                device_count = "unavailable"
        else:
            device_count = "0"
        ai_runtime: str
        if paths.settings.is_file():
            try:
                selected = ApplicationSettingsStore(paths).load().ai.provider
                ai_runtime = "auto" if selected == "openai" else selected
            except (OSError, StateError):
                ai_runtime = "unavailable"
        else:
            ai_runtime = "not configured"
        self._console.print(f"NetSage {__version__}")
        self._console.print()
        self._console.print(f"FortiOS devices: {device_count}")
        self._console.print(f"AI provider selection: {ai_runtime}")
        self._console.print("Mode: Observe")
        self._console.print()
        self._console.print("Type 'help' for commands. Type 'exit' or 'quit' to leave.")
        self._console.print()


def run_interactive_shell(application: typer.Typer) -> None:
    NetSageInteractiveShell(application).run()
