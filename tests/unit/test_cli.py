from pathlib import Path

import pytest
from typer.testing import CliRunner

from netsage import __version__
from netsage.cli import main as main_module
from netsage.cli.main import app
from netsage.distribution import InstallResult, UninstallResult
from netsage.drivers.fortios import FortiOSSnapshot, SSHHostKeyPin
from netsage.models import DeviceFacts, HealthStatus, SystemHealth

runner = CliRunner()


def test_version() -> None:
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout


def test_help_lists_core_commands() -> None:
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    for command in ("setup", "device", "devices", "doctor", "fortigate"):
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


def test_fortigate_live_test_keeps_password_out_of_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_value = "temporary" + "-test-value"
    pin = SSHHostKeyPin(
        algorithm="ssh-rsa",
        fingerprint="SHA256:synthetic",
        known_hosts_data=b"synthetic host key",
    )

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return pin

    async def collect(
        _host: str,
        _port: int,
        _username: str,
        password: str,
        _pin: SSHHostKeyPin,
    ) -> FortiOSSnapshot:
        assert password == credential_value
        return FortiOSSnapshot(
            facts=DeviceFacts(
                device_id="fortigate-live",
                vendor="Fortinet",
                model="FortiGate-Synthetic",
                os_version="7.4.5",
            ),
            interfaces=(),
            vlans=(),
            arp_entries=(),
            routes=(),
            health=SystemHealth(
                device_id="fortigate-live",
                status=HealthStatus.HEALTHY,
            ),
            firewall_policies=(),
        )

    monkeypatch.setattr(main_module, "discover_ssh_host_key", discover)
    monkeypatch.setattr(main_module, "_collect_fortigate_snapshot", collect)
    result = runner.invoke(
        app,
        ["fortigate", "live-test"],
        input=f"192.0.2.1\n22022\ny\nreadonly\n{credential_value}\n",
    )
    assert result.exit_code == 0
    assert "No configuration changes were made" in result.stdout
    assert "process memory only" in result.stdout
    assert credential_value not in result.stdout


def test_fortigate_live_test_can_abort_before_requesting_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return SSHHostKeyPin(
            algorithm="ssh-rsa",
            fingerprint="SHA256:synthetic",
            known_hosts_data=b"synthetic host key",
        )

    monkeypatch.setattr(main_module, "discover_ssh_host_key", discover)
    result = runner.invoke(
        app,
        ["fortigate", "live-test"],
        input="192.0.2.1\n22022\nn\n",
    )
    assert result.exit_code == 1
    assert "before credentials were requested" in result.stdout
    assert "Username" not in result.stdout
