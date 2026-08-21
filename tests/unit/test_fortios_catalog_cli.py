import pytest
from typer.testing import CliRunner

from netsage.cli import fortios_catalog_commands
from netsage.cli.main import app
from netsage.drivers.fortios.catalog import FortiOSCatalogError

runner = CliRunner()


def test_catalog_search_show_and_coverage_are_local_read_only_commands() -> None:
    searched = runner.invoke(
        app,
        ["fortios", "commands", "search", "execute ping", "--limit", "3"],
    )
    shown = runner.invoke(
        app,
        ["fortios", "commands", "show", "fortios.execute.ping"],
    )
    coverage = runner.invoke(app, ["fortios", "commands", "coverage"])

    for result in (searched, shown, coverage):
        assert result.exit_code == 0, result.output
    assert "fortios.execute.ping" in searched.output
    assert "local catalog only; no device connection" in searched.output
    assert "Classification" in shown.output
    assert "diagnostic" in shown.output
    assert "Executable in default Observe" in shown.output
    assert "Execution disposition" in shown.output
    assert "Execution reason" in shown.output
    assert "AI-visible" in shown.output
    assert "No command was executed" in shown.output
    assert "Commands catalogued" in coverage.output
    assert "19030" in coverage.output
    assert "does not mean 100% executable" in coverage.output


def test_catalog_show_rejects_unknown_id_without_execution() -> None:
    result = runner.invoke(
        app,
        ["fortios", "commands", "show", "fortios.execute.not-documented"],
    )

    assert result.exit_code == 1
    assert "Unknown FortiOS command ID" in result.output
    assert "not-documented" not in result.output


def test_catalog_cli_bounds_search_arguments() -> None:
    blank = runner.invoke(app, ["fortios", "commands", "search", "   "])
    excessive = runner.invoke(
        app,
        ["fortios", "commands", "search", "route", "--limit", "1001"],
    )

    assert blank.exit_code == 1
    assert "search failed" in blank.output
    assert excessive.exit_code == 2


def test_catalog_cli_reports_bounded_manifest_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable():
        raise FortiOSCatalogError("synthetic raw details")

    monkeypatch.setattr(fortios_catalog_commands, "_registry", unavailable)

    result = runner.invoke(app, ["fortios", "commands", "coverage"])

    assert result.exit_code == 1
    assert "catalog is unavailable" in result.output
    assert "synthetic raw details" not in result.output
