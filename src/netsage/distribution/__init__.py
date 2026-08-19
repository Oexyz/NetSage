"""Self-contained distribution installation helpers."""

from netsage.distribution.windows import (
    InstallResult,
    UninstallResult,
    install_current_executable,
    uninstall_current_executable,
)

__all__ = [
    "InstallResult",
    "UninstallResult",
    "install_current_executable",
    "uninstall_current_executable",
]
