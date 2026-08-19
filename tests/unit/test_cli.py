from pathlib import Path

import pytest
from typer.testing import CliRunner

from netsage import __version__
from netsage.cli import main as main_module
from netsage.cli.main import app
from netsage.distribution import InstallResult, UninstallResult

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_core_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("setup", "device", "devices", "doctor"):
        assert command in result.stdout


def test_doctor() -> None:
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "Python" in result.stdout
    assert "Credential Store" in result.stdout


def test_safe_placeholder_commands() -> None:
    expected = {
        "setup": "no credentials were changed",
        "device": "not implemented",
        "devices": "not implemented",
    }
    for command, message in expected.items():
        result = runner.invoke(app, [command])
        assert result.exit_code == 0
        assert message in result.stdout


def test_module_entrypoint() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0


def test_install_alias(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable = tmp_path / "netsage.exe"
    monkeypatch.setattr(
        main_module,
        "install_current_executable",
        lambda: InstallResult(executable=executable, path_changed=True),
    )
    result = runner.invoke(app, ["-install"])
    assert result.exit_code == 0
    assert "Installed NetSage" in result.stdout


def test_uninstall_command(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    executable = tmp_path / "netsage.exe"
    monkeypatch.setattr(
        main_module,
        "uninstall_current_executable",
        lambda: UninstallResult(
            executable=executable,
            path_changed=True,
            executable_removed=True,
        ),
    )
    result = runner.invoke(app, ["uninstall-path"])
    assert result.exit_code == 0
    assert "Removed" in result.stdout
