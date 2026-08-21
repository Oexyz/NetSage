import os
import subprocess
from collections import deque
from io import StringIO
from pathlib import Path

import pytest
from rich.console import Console
from typer.testing import CliRunner

from netsage.cli import main as main_module
from netsage.cli import state_commands
from netsage.cli.main import app
from netsage.cli.shell import NetSageInteractiveShell
from netsage.state import LocalState, StatePaths

runner = CliRunner()


def isolated_state(tmp_path: Path) -> LocalState:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    return state


def test_no_argument_launch_help_nested_command_and_exit() -> None:
    result = runner.invoke(
        app,
        [],
        input="help\nhelp fortios\nfortios commands coverage\nexit\n",
    )

    assert result.exit_code == 0, result.output
    assert "NetSage 0.1.0" in result.output
    assert "Mode: Observe" in result.output
    assert "Open-source AI Network & Infrastructure Investigator" in result.output
    assert "Inspect the generated FortiOS CLI knowledge catalog" in result.output
    assert "Commands catalogued" in result.output


@pytest.mark.parametrize("exit_command", ["exit", "quit"])
def test_exit_and_quit(exit_command: str) -> None:
    result = runner.invoke(app, [], input=f"{exit_command}\n")

    assert result.exit_code == 0
    assert "netsage>" in result.output


def test_eof_exits_cleanly() -> None:
    output = StringIO()

    def eof(_prompt: str) -> str:
        raise EOFError

    NetSageInteractiveShell(
        app,
        input_reader=eof,
        console=Console(file=output, force_terminal=False),
    ).run()

    assert "Mode: Observe" in output.getvalue()


def test_idle_ctrl_c_cancels_input_and_keeps_shell_alive() -> None:
    output = StringIO()
    inputs: deque[str | BaseException] = deque((KeyboardInterrupt(), "exit"))

    def reader(_prompt: str) -> str:
        value = inputs.popleft()
        if isinstance(value, BaseException):
            raise value
        return value

    NetSageInteractiveShell(
        app,
        input_reader=reader,
        console=Console(file=output, force_terminal=False),
    ).run()

    assert "Input cancelled" in output.getvalue()


def test_quoted_ask_arguments_use_existing_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        main_module,
        "ask_device",
        lambda device, question: calls.append((device, question)),
    )

    one_shot = runner.invoke(
        app,
        ["ask", "firewall-example", "Why is the default route missing?"],
    )
    interactive = runner.invoke(
        app,
        [],
        input='ask firewall-example "Why is the default route missing?"\nexit\n',
    )

    assert one_shot.exit_code == 0
    assert interactive.exit_code == 0
    assert calls == [
        ("firewall-example", "Why is the default route missing?"),
        ("firewall-example", "Why is the default route missing?"),
    ]


def test_devices_one_shot_and_shell_share_handler_and_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    calls = 0

    def state_factory() -> LocalState:
        nonlocal calls
        calls += 1
        return state

    monkeypatch.setattr(state_commands, "_state", state_factory)

    one_shot = runner.invoke(app, ["devices"])
    interactive = runner.invoke(app, [], input="devices\nexit\n")

    assert one_shot.exit_code == 0
    assert interactive.exit_code == 0
    assert "NetSage devices" in one_shot.output
    assert "NetSage devices" in interactive.output
    assert calls == 2


def test_unknown_and_os_shell_input_never_executes_processes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("OS execution must never be reached")

    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)

    result = runner.invoke(
        app,
        [],
        input="foobar\nwhoami\nrm -rf example\npowershell Get-Process\nexit\n",
    )

    assert result.exit_code == 0
    for command in ("foobar", "whoami", "rm", "powershell"):
        assert f"Unknown command: {command}" in result.output
    assert "Type 'help' to list available commands." in result.output


def test_shell_startup_performs_no_device_or_ai_network_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_network(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("shell startup must not access the network")

    monkeypatch.setattr(main_module, "discover_ssh_host_key", forbidden_network)

    result = runner.invoke(app, [], input="exit\n")

    assert result.exit_code == 0
    assert "Mode: Observe" in result.output


def test_help_and_version_remain_non_interactive() -> None:
    help_result = runner.invoke(app, ["--help"])
    version_result = runner.invoke(app, ["--version"])

    assert help_result.exit_code == 0
    assert version_result.exit_code == 0
    assert "netsage>" not in help_result.output
    assert "netsage>" not in version_result.output
