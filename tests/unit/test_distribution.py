import sys
from pathlib import Path

import pytest

from netsage.distribution import windows


def test_add_path_entry_appends_once() -> None:
    updated, changed = windows.add_path_entry(r"C:\Windows;", Path(r"C:\Users\test\bin"))
    assert changed is True
    assert updated.endswith(r"C:\Users\test\bin;")

    unchanged, changed_again = windows.add_path_entry(updated, Path(r"c:\users\test\bin"))
    assert changed_again is False
    assert unchanged == updated


def test_remove_path_entry_removes_normalized_matches() -> None:
    updated, changed = windows.remove_path_entry(
        r"C:\Windows;C:\Users\test\bin;", Path(r"c:\users\test\bin")
    )
    assert changed is True
    assert updated == "C:\\Windows;"


def test_install_executable_copies_and_updates_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = tmp_path / "download" / "netsage.exe"
    source.parent.mkdir()
    source.write_bytes(b"standalone-binary")
    local_app_data = tmp_path / "local"
    writes: list[tuple[str, int]] = []

    monkeypatch.setattr(windows, "_read_user_path", lambda: (r"C:\Windows;", 2))
    monkeypatch.setattr(
        windows, "_write_user_path", lambda value, kind: writes.append((value, kind))
    )
    monkeypatch.setattr(windows, "_notify_environment_change", lambda: None)

    result = windows.install_executable(source, local_app_data)

    assert result.executable.read_bytes() == b"standalone-binary"
    assert result.path_changed is True
    assert writes == [(f"C:\\Windows;{local_app_data.resolve()}\\NetSage\\bin;", 2)]


def test_install_executable_rejects_non_executable(tmp_path: Path) -> None:
    source = tmp_path / "netsage.py"
    source.write_text("pass", encoding="utf-8")
    with pytest.raises(windows.DistributionInstallError, match=r"\.exe"):
        windows.install_executable(source, tmp_path / "local")


def test_install_current_executable_uses_frozen_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "download" / "netsage.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"binary")
    local_app_data = tmp_path / "local"
    expected = windows.InstallResult(local_app_data / "NetSage/bin/netsage.exe", True)

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(windows, "install_executable", lambda source, root: expected)

    assert windows.install_current_executable() == expected


def test_install_current_executable_fails_outside_windows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(windows.DistributionInstallError, match="Windows only"):
        windows.install_current_executable()


def test_uninstall_removes_path_and_non_running_binary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    local_app_data = tmp_path / "local"
    install_dir = local_app_data / "NetSage" / "bin"
    install_dir.mkdir(parents=True)
    executable = install_dir / "netsage.exe"
    executable.write_bytes(b"old-binary")
    writes: list[tuple[str, int]] = []

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(tmp_path / "downloaded.exe"))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(windows, "_read_user_path", lambda: (f"C:\\Windows;{install_dir};", 2))
    monkeypatch.setattr(
        windows, "_write_user_path", lambda value, kind: writes.append((value, kind))
    )
    monkeypatch.setattr(windows, "_notify_environment_change", lambda: None)

    result = windows.uninstall_current_executable()

    assert result.executable_removed is True
    assert result.path_changed is True
    assert not executable.exists()
    assert writes == [("C:\\Windows;", 2)]


def test_uninstall_retains_running_binary(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    local_app_data = tmp_path / "local"
    install_dir = local_app_data / "NetSage" / "bin"
    install_dir.mkdir(parents=True)
    executable = install_dir / "netsage.exe"
    executable.write_bytes(b"running-binary")

    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", str(executable))
    monkeypatch.setenv("LOCALAPPDATA", str(local_app_data))
    monkeypatch.setattr(windows, "_read_user_path", lambda: ("C:\\Windows;", 2))

    result = windows.uninstall_current_executable()

    assert result.executable_removed is False
    assert result.path_changed is False
    assert executable.exists()
