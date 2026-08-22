from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import pytest
from typer.testing import CliRunner

from netsage.broker import AuditEvent, AuditResult
from netsage.cli import state_commands
from netsage.cli.main import app
from netsage.credentials import (
    CredentialProfile,
    CredentialSecretStore,
    CredentialSecretUnavailableError,
)
from netsage.drivers.fortios import SSHHostKeyPin
from netsage.history import SQLiteAuditSink, SQLiteInvestigationStore
from netsage.investigations import (
    FortiOSInvestigationFocus,
    Investigation,
    InvestigationKind,
    InvestigationReport,
    InvestigationStatus,
)
from netsage.models import DeviceFacts, DeviceRef
from netsage.onboarding import CheckStatus, DeviceReadiness, DeviceTestResult
from netsage.policies import AuthorizationDecision
from netsage.state import LocalState, SSHHostTrustRecord, StatePaths

runner = CliRunner()
CANARY = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_CLI"


class MemorySecretStore(CredentialSecretStore):
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.reads = 0

    def set_secret(self, profile_name: str, secret: str) -> None:
        self.values[profile_name] = secret

    def get_secret(self, profile_name: str) -> str:
        self.reads += 1
        try:
            return self.values[profile_name]
        except KeyError as error:
            raise CredentialSecretUnavailableError("Credential secret unavailable") from error

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        if profile_name not in self.values and not missing_ok:
            raise CredentialSecretUnavailableError("Credential secret unavailable")
        self.values.pop(profile_name, None)


class FakeDeviceService:
    def __init__(self, device: DeviceRef, trust: SSHHostTrustRecord, state: LocalState) -> None:
        self.device = device
        self.trust = trust
        self.state = state
        self.removed = False
        self.trust_replaced = False
        self.added = False
        self.last_focus = FortiOSInvestigationFocus.HEALTH
        self.pin = SSHHostKeyPin(
            algorithm=trust.algorithm,
            fingerprint=trust.fingerprint,
            known_hosts_data=b"192.0.2.10 ssh-ed25519 synthetic-public-key\n",
        )

    def list_devices(self) -> tuple[DeviceRef, ...]:
        return (self.device,)

    def show_device(self, _name: str) -> tuple[DeviceRef, SSHHostTrustRecord]:
        return self.device, self.trust

    async def discover_host_key(self, *, host: str, port: int) -> SSHHostKeyPin:
        assert host == self.device.host
        assert port == self.device.port
        return self.pin

    async def add_device(self, **_kwargs: object) -> DeviceTestResult:
        self.added = True
        return ready_result()

    async def test_device(self, _name: str) -> DeviceTestResult:
        return ready_result()

    def remove_device(self, _name: str) -> None:
        self.removed = True

    async def discover_replacement_key(self, _name: str) -> tuple[DeviceRef, SSHHostKeyPin]:
        return self.device, self.pin

    def replace_trust(self, _device: DeviceRef, _pin: SSHHostKeyPin) -> None:
        self.trust_replaced = True

    async def investigate(
        self,
        _name: str,
        *,
        persist: bool = True,
        focus: FortiOSInvestigationFocus = FortiOSInvestigationFocus.HEALTH,
    ) -> InvestigationReport:
        self.last_focus = focus
        now = datetime(2026, 8, 20, 20, 30, tzinfo=UTC)
        report = InvestigationReport(
            investigation=Investigation(
                investigation_id=UUID(int=100),
                device_id=self.device.name,
                kind=InvestigationKind.FORTIGATE_HEALTH,
                started_at=now,
            ),
            completed_at=now,
            status=InvestigationStatus.HEALTHY,
            evidence_ids=(),
        )
        if persist:
            SQLiteInvestigationStore(self.state.history).add(report)
        return report


def ready_result() -> DeviceTestResult:
    return DeviceTestResult(
        device_id="fortigate-example",
        readiness=DeviceReadiness.READY,
        host_key=CheckStatus.PASS,
        credential=CheckStatus.PASS,
        authentication=CheckStatus.PASS,
        fortios=CheckStatus.PASS,
        facts=CheckStatus.PASS,
        device_facts=DeviceFacts(
            device_id="fortigate-example",
            vendor="Fortinet",
            model="Synthetic",
            os_version="test",
        ),
        detail="Device is ready",
    )


def isolated_state(tmp_path: Path) -> LocalState:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    return state


def fake_device() -> tuple[DeviceRef, SSHHostTrustRecord]:
    device = DeviceRef(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        platform="fortios",
        credential_ref="fortigate-readonly",
        trust_ref="fortigate-example",
    )
    trust = SSHHostTrustRecord(
        name="fortigate-example",
        host=device.host,
        port=device.port,
        algorithm="ssh-ed25519",
        fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    return device, trust


def test_credential_cli_add_list_show_remove_never_reveals_secret(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    secrets = MemorySecretStore()
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    monkeypatch.setattr(state_commands, "_secrets", lambda: secrets)

    added = runner.invoke(
        app,
        ["credentials", "add"],
        input=f"fortigate-readonly\n\nnetsage-ro\n{CANARY}\n{CANARY}\n",
    )
    listed = runner.invoke(app, ["credentials", "list"])
    shown = runner.invoke(app, ["credentials", "show", "fortigate-readonly"])

    assert added.exit_code == 0
    assert listed.exit_code == 0
    assert shown.exit_code == 0
    combined = added.stdout + listed.stdout + shown.stdout
    assert CANARY not in combined
    assert "netsage-ro" in listed.stdout
    assert "stored securely" in shown.stdout
    assert secrets.reads == 0
    assert CANARY not in state.paths.credential_profiles.read_text(encoding="utf-8")
    assert "reveal" not in runner.invoke(app, ["credentials", "--help"]).stdout

    rotated = runner.invoke(
        app,
        ["credentials", "rotate", "fortigate-readonly"],
        input="replacement-secret\nreplacement-secret\n",
    )
    assert rotated.exit_code == 0
    assert secrets.values["fortigate-readonly"] == "replacement-secret"
    assert "replacement-secret" not in state.paths.credential_profiles.read_text(encoding="utf-8")

    removed = runner.invoke(
        app,
        ["credentials", "remove", "fortigate-readonly"],
        input="y\n",
    )
    assert removed.exit_code == 0
    assert state.credentials.load().profiles == {}
    assert secrets.values == {}


def test_device_cli_add_list_show_test_investigate_remove_and_trust_reset(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    state.credentials.add(CredentialProfile(name="fortigate-readonly", username="netsage-ro"))
    device, trust = fake_device()
    state.host_trust.add(trust)
    service = FakeDeviceService(device, trust, state)
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    monkeypatch.setattr(state_commands, "_device_service", lambda _state: service)

    added = runner.invoke(
        app,
        ["device", "add"],
        input="fortigate-example\n\n192.0.2.10\n22\nfortigate-readonly\ny\n",
    )
    listed = runner.invoke(app, ["devices"])
    shown = runner.invoke(app, ["device", "show", "fortigate-example"])
    tested = runner.invoke(app, ["device", "test", "fortigate-example"])
    investigated = runner.invoke(app, ["investigate", "fortigate-example"])
    focused = runner.invoke(
        app,
        ["investigate", "fortigate-example", "--ephemeral", "--focus", "ha"],
    )
    reset = runner.invoke(
        app,
        ["device", "trust-reset", "fortigate-example"],
        input="y\n",
    )
    removed = runner.invoke(
        app,
        ["device", "remove", "fortigate-example"],
        input="y\n",
    )

    results = {
        "add": added,
        "list": listed,
        "show": shown,
        "test": tested,
        "investigate": investigated,
        "trust-reset": reset,
        "remove": removed,
    }
    for label, result in results.items():
        assert result.exit_code == 0, f"{label}: {result.stdout} ({result.exception!r})"
    assert "Fingerprint" in added.stdout
    assert "fortigate-example" in listed.stdout
    assert "stored" in shown.stdout
    assert "READY" in tested.stdout
    assert "No configuration changes were made" in investigated.stdout
    assert "Investigation saved" in investigated.stdout
    assert focused.exit_code == 0
    assert service.last_focus is FortiOSInvestigationFocus.HA
    assert service.trust_replaced is True
    assert service.removed is True
    assert CANARY not in "".join(
        result.stdout for result in (added, listed, shown, tested, investigated, reset, removed)
    )


def test_device_cli_rejects_unsupported_platform_before_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    result = runner.invoke(app, ["device", "add"], input="switch-example\naruba\n")
    assert result.exit_code == 1
    assert "Only FortiOS" in result.stdout


def test_device_add_does_not_authenticate_or_persist_before_host_key_review(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    state.credentials.add(CredentialProfile(name="fortigate-readonly", username="netsage-ro"))
    device, trust = fake_device()
    service = FakeDeviceService(device, trust, state)
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    monkeypatch.setattr(state_commands, "_device_service", lambda _state: service)

    result = runner.invoke(
        app,
        ["device", "add"],
        input="fortigate-example\n\n192.0.2.10\n22\nfortigate-readonly\nn\n",
    )
    assert result.exit_code == 1
    assert "Device was not saved" in result.stdout
    assert service.added is False


def test_ephemeral_investigation_writes_no_history(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    device, trust = fake_device()
    service = FakeDeviceService(device, trust, state)
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    monkeypatch.setattr(state_commands, "_device_service", lambda _state: service)

    result = runner.invoke(app, ["investigate", device.name, "--ephemeral"])
    assert result.exit_code == 0
    assert "History persistence: disabled" in result.stdout
    assert SQLiteInvestigationStore(state.history).list() == ()
    assert SQLiteAuditSink(state.history).list() == ()


def test_history_and_audit_cli_reload_show_and_remove_without_network(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    device, trust = fake_device()
    service = FakeDeviceService(device, trust, state)
    monkeypatch.setattr(state_commands, "_state", lambda: state)
    monkeypatch.setattr(state_commands, "_device_service", lambda _state: service)
    run = runner.invoke(app, ["investigate", device.name])
    report_id = SQLiteInvestigationStore(state.history).list()[0].investigation_id
    SQLiteAuditSink(state.history).record(
        AuditEvent(
            timestamp=datetime(2026, 8, 21, 8, 0, tzinfo=UTC),
            user="operator",
            ai_provider=None,
            tool="get_interfaces",
            device=device.name,
            safe_arguments={"device": device.name},
            result=AuditResult.SUCCESS,
            duration_ms=1,
            authorization=AuthorizationDecision(allowed=True, reason="read only"),
        )
    )

    listed = runner.invoke(app, ["investigations"])
    shown = runner.invoke(app, ["investigation", "show", str(report_id)])
    audit = runner.invoke(app, ["audit", "--limit", "10"])
    removed = runner.invoke(
        app,
        ["investigation", "remove", str(report_id)],
        input="y\n",
    )
    for result in (run, listed, shown, audit, removed):
        assert result.exit_code == 0
    assert str(report_id) in listed.stdout
    assert "No configuration changes were made" in shown.stdout
    assert "get_interfaces" in audit.stdout
    assert "Audit events were retained" in removed.stdout
    assert SQLiteInvestigationStore(state.history).list() == ()
    assert len(SQLiteAuditSink(state.history).list()) == 1
