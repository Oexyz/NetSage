"""Safe per-user installation for the frozen Windows executable."""

from __future__ import annotations

import ntpath
import os
import shutil
import sys
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any


class DistributionInstallError(RuntimeError):
    """Raised when a standalone distribution cannot be installed safely."""


@dataclass(frozen=True, slots=True)
class InstallResult:
    """Outcome of a user-level executable installation."""

    executable: Path
    path_changed: bool


@dataclass(frozen=True, slots=True)
class UninstallResult:
    """Outcome of removing the user-level executable installation."""

    executable: Path
    path_changed: bool
    executable_removed: bool


def _normalized_path(value: str) -> str:
    return ntpath.normcase(ntpath.normpath(os.path.expandvars(value.strip().strip('"'))))


def add_path_entry(path_value: str, entry: Path) -> tuple[str, bool]:
    """Append one directory to a semicolon-delimited PATH without duplicates."""
    entries = [item for item in path_value.split(";") if item.strip()]
    normalized_entry = _normalized_path(str(entry))
    if any(_normalized_path(item) == normalized_entry for item in entries):
        return path_value, False
    entries.append(str(entry))
    return ";".join(entries) + ";", True


def remove_path_entry(path_value: str, entry: Path) -> tuple[str, bool]:
    """Remove all normalized matches from a semicolon-delimited PATH."""
    normalized_entry = _normalized_path(str(entry))
    entries = [item for item in path_value.split(";") if item.strip()]
    retained = [item for item in entries if _normalized_path(item) != normalized_entry]
    if len(retained) == len(entries):
        return path_value, False
    return (";".join(retained) + ";" if retained else ""), True


def _read_user_path() -> tuple[str, int]:
    winreg: Any = import_module("winreg")

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        try:
            value, value_type = winreg.QueryValueEx(key, "Path")
        except FileNotFoundError:
            return "", winreg.REG_EXPAND_SZ
    return str(value), int(value_type)


def _write_user_path(value: str, value_type: int) -> None:
    winreg: Any = import_module("winreg")

    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, "Path", 0, value_type, value)


def _notify_environment_change() -> None:
    """Best-effort broadcast so newly launched applications see the new PATH."""
    try:
        ctypes: Any = import_module("ctypes")
        send_message = ctypes.windll.user32.SendMessageTimeoutW
        send_message(0xFFFF, 0x001A, 0, "Environment", 0x0002, 5000, None)
    except (AttributeError, OSError):
        pass


def install_executable(source: Path, local_app_data: Path) -> InstallResult:
    """Copy a trusted executable into the fixed per-user NetSage directory."""
    source = source.resolve(strict=True)
    if source.suffix.casefold() != ".exe":
        raise DistributionInstallError("The Windows distribution must be an .exe file")

    install_dir = (local_app_data / "NetSage" / "bin").resolve()
    expected_parent = local_app_data.resolve()
    if expected_parent not in install_dir.parents:
        raise DistributionInstallError("Refusing an installation path outside LOCALAPPDATA")

    install_dir.mkdir(parents=True, exist_ok=True)
    destination = install_dir / "netsage.exe"
    if source != destination:
        temporary = install_dir / "netsage.exe.new"
        shutil.copy2(source, temporary)
        temporary.replace(destination)

    current_path, value_type = _read_user_path()
    updated_path, changed = add_path_entry(current_path, install_dir)
    if changed:
        _write_user_path(updated_path, value_type)
        _notify_environment_change()
    return InstallResult(executable=destination, path_changed=changed)


def install_current_executable() -> InstallResult:
    """Install the currently running frozen executable for the current user."""
    if sys.platform != "win32":
        raise DistributionInstallError("install-path is currently supported on Windows only")
    if not getattr(sys, "frozen", False):
        raise DistributionInstallError(
            "install-path requires the standalone netsage.exe distribution"
        )
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise DistributionInstallError("LOCALAPPDATA is unavailable")
    return install_executable(Path(sys.executable), Path(local_app_data))


def uninstall_current_executable() -> UninstallResult:
    """Remove the fixed install directory from PATH and delete it when safe."""
    if sys.platform != "win32":
        raise DistributionInstallError("uninstall-path is currently supported on Windows only")
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        raise DistributionInstallError("LOCALAPPDATA is unavailable")

    install_dir = (Path(local_app_data) / "NetSage" / "bin").resolve()
    executable = install_dir / "netsage.exe"
    current_path, value_type = _read_user_path()
    updated_path, changed = remove_path_entry(current_path, install_dir)
    if changed:
        _write_user_path(updated_path, value_type)
        _notify_environment_change()

    running_executable = Path(sys.executable).resolve()
    removed = False
    if executable.is_file() and executable != running_executable:
        executable.unlink()
        removed = True
        try:
            install_dir.rmdir()
            install_dir.parent.rmdir()
        except OSError:
            pass
    return UninstallResult(executable=executable, path_changed=changed, executable_removed=removed)
