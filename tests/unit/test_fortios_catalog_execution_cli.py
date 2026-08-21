from pathlib import Path

import pytest
from typer.testing import CliRunner

from netsage.cli import fortios_catalog_commands
from netsage.cli.main import app
from netsage.credentials import CredentialProfile
from netsage.drivers.fortios.catalog import FortiOSCatalogInvocation
from netsage.history import SQLiteAuditSink
from netsage.models import DeviceRef
from netsage.onboarding import PreparedFortiOSRuntime
from netsage.security import SecretRedactor
from netsage.state import LocalState, SSHHostTrustRecord, StatePaths

runner = CliRunner()
CANARY = "CATALOG_CLI_CANARY_SECRET"
COMMAND_ID = "fortios.execute.cpu.show"


class FakeCatalogDriver:
    def __init__(self, outputs: tuple[str, ...] = ("synthetic CPU output",)) -> None:
        self.outputs = list(outputs)
        self.requests: list[FortiOSCatalogInvocation] = []

    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str:
        self.requests.append(request)
        if not self.outputs:
            raise AssertionError("No scripted CLI catalog output")
        return self.outputs.pop(0)


class FakeRuntimeFactory:
    prepared: PreparedFortiOSRuntime
    prepares = 0

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def prepare(self, _device: DeviceRef) -> PreparedFortiOSRuntime:
        type(self).prepares += 1
        return type(self).prepared


def isolated_state(tmp_path: Path) -> tuple[LocalState, DeviceRef]:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.credentials.add(CredentialProfile(name="readonly-profile", username="readonly"))
    device = DeviceRef(
        name="firewall-example",
        host="192.0.2.10",
        platform="fortios",
        credential_ref="readonly-profile",
        trust_ref="firewall-example",
    )
    state.host_trust.add(
        SSHHostTrustRecord(
            name=device.name,
            host=device.host,
            port=device.port,
            algorithm="ssh-ed25519",
            fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    state.inventory.add(device)
    return state, device


def test_one_shot_and_repl_dry_run_share_handler_without_runtime_prepare(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, _device = isolated_state(tmp_path)
    FakeRuntimeFactory.prepares = 0
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)
    monkeypatch.setattr(
        fortios_catalog_commands,
        "FortiOSRuntimeFactory",
        FakeRuntimeFactory,
    )

    one_shot = runner.invoke(
        app,
        ["fortios", "run", "firewall-example", COMMAND_ID, "--dry-run"],
    )
    interactive = runner.invoke(
        app,
        [],
        input=f"fortios run firewall-example {COMMAND_ID} --dry-run\nexit\n",
    )

    assert one_shot.exit_code == 0, one_shot.output
    assert interactive.exit_code == 0, interactive.output
    for output in (one_shot.output, interactive.output):
        assert "execute cpu show" in output
        assert "Dry run only" in output
        assert "AI-visible" in output
    assert FakeRuntimeFactory.prepares == 0


def test_dry_run_json_is_secret_free_and_structured(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, _device = isolated_state(tmp_path)
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)

    result = runner.invoke(
        app,
        ["fortios", "run", "firewall-example", COMMAND_ID, "--dry-run", "--json"],
    )

    assert result.exit_code == 0
    assert '"rendered_command": "execute cpu show"' in result.output
    assert '"ai_visible": false' in result.output
    assert CANARY not in result.output


def test_actual_one_shot_execution_redacts_output_and_writes_safe_audit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, device = isolated_state(tmp_path)
    driver = FakeCatalogDriver((f"CPU ok token={CANARY}",))
    FakeRuntimeFactory.prepares = 0
    FakeRuntimeFactory.prepared = PreparedFortiOSRuntime(
        device=device,
        driver=driver,  # type: ignore[arg-type]
        redactor=SecretRedactor(known_secrets=(CANARY,)),
    )
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)
    monkeypatch.setattr(
        fortios_catalog_commands,
        "FortiOSRuntimeFactory",
        FakeRuntimeFactory,
    )

    result = runner.invoke(
        app,
        ["fortios", "run", device.name, COMMAND_ID],
    )

    assert result.exit_code == 0, result.output
    assert "<REDACTED>" in result.output
    assert CANARY not in result.output
    assert "Output was not persisted" in result.output
    assert FakeRuntimeFactory.prepares == 1
    events = SQLiteAuditSink(state.history).list(limit=10)
    assert len(events) == 1
    assert events[0].tool == f"fortios_catalog:{COMMAND_ID}"
    assert CANARY not in events[0].model_dump_json()
    assert CANARY.encode() not in state.paths.history.read_bytes()


def test_actual_repl_and_one_shot_execution_are_equivalent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, device = isolated_state(tmp_path)
    driver = FakeCatalogDriver(("one-shot output", "repl output"))
    FakeRuntimeFactory.prepares = 0
    FakeRuntimeFactory.prepared = PreparedFortiOSRuntime(
        device=device,
        driver=driver,  # type: ignore[arg-type]
        redactor=SecretRedactor(),
    )
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)
    monkeypatch.setattr(
        fortios_catalog_commands,
        "FortiOSRuntimeFactory",
        FakeRuntimeFactory,
    )

    one_shot = runner.invoke(app, ["fortios", "run", device.name, COMMAND_ID])
    interactive = runner.invoke(
        app,
        [],
        input=f"fortios run {device.name} {COMMAND_ID}\nexit\n",
    )

    assert one_shot.exit_code == 0, one_shot.output
    assert interactive.exit_code == 0, interactive.output
    assert "one-shot output" in one_shot.output
    assert "repl output" in interactive.output
    assert [request.command_id for request in driver.requests] == [COMMAND_ID, COMMAND_ID]
    assert FakeRuntimeFactory.prepares == 2
    assert len(SQLiteAuditSink(state.history).list(limit=10)) == 2


def test_actual_json_output_is_sanitized_and_not_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, device = isolated_state(tmp_path)
    FakeRuntimeFactory.prepared = PreparedFortiOSRuntime(
        device=device,
        driver=FakeCatalogDriver((f"token={CANARY}",)),  # type: ignore[arg-type]
        redactor=SecretRedactor(known_secrets=(CANARY,)),
    )
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)
    monkeypatch.setattr(
        fortios_catalog_commands,
        "FortiOSRuntimeFactory",
        FakeRuntimeFactory,
    )

    result = runner.invoke(
        app,
        ["fortios", "run", device.name, COMMAND_ID, "--json"],
    )

    assert result.exit_code == 0
    assert '"output_type": "sanitized_text"' in result.output
    assert '"evidence_created": false' in result.output
    assert '"persisted": false' in result.output
    assert '"ai_visible": false' in result.output
    assert CANARY not in result.output


def test_policy_denial_happens_before_runtime_or_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, device = isolated_state(tmp_path)
    FakeRuntimeFactory.prepares = 0
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)
    monkeypatch.setattr(
        fortios_catalog_commands,
        "FortiOSRuntimeFactory",
        FakeRuntimeFactory,
    )

    result = runner.invoke(
        app,
        ["fortios", "run", device.name, "fortios.config.system.interface"],
    )

    assert result.exit_code == 1
    assert "POLICY_DENIED" in result.output
    assert FakeRuntimeFactory.prepares == 0


def test_cli_rejects_malformed_named_argument_without_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state, device = isolated_state(tmp_path)
    FakeRuntimeFactory.prepares = 0
    monkeypatch.setattr(fortios_catalog_commands, "_state", lambda: state)

    result = runner.invoke(
        app,
        ["fortios", "run", device.name, COMMAND_ID, "--arg", "not-named"],
    )

    assert result.exit_code == 1
    assert "INVALID_ARGUMENT" in result.output
    assert FakeRuntimeFactory.prepares == 0
