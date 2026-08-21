"""Platform-appropriate user-level paths for non-secret NetSage state."""

import os
import sys
from dataclasses import dataclass
from pathlib import Path


def default_state_directory(
    *,
    platform: str | None = None,
    environment: dict[str, str] | None = None,
    home: Path | None = None,
) -> Path:
    platform_name = platform or sys.platform
    values = environment if environment is not None else dict(os.environ)
    user_home = home or Path.home()
    if platform_name == "win32":
        local_app_data = values.get("LOCALAPPDATA")
        base = Path(local_app_data) if local_app_data else user_home / "AppData" / "Local"
        return base / "NetSage"
    if platform_name == "darwin":
        return user_home / "Library" / "Application Support" / "NetSage"
    xdg_config_home = values.get("XDG_CONFIG_HOME")
    base = Path(xdg_config_home) if xdg_config_home else user_home / ".config"
    return base / "netsage"


@dataclass(frozen=True, slots=True)
class StatePaths:
    root: Path
    settings: Path
    inventory: Path
    credential_profiles: Path
    host_trust: Path
    history: Path

    @classmethod
    def from_root(cls, root: Path) -> "StatePaths":
        normalized = root.expanduser().resolve()
        return cls(
            root=normalized,
            settings=normalized / "config.yaml",
            inventory=normalized / "inventory.yaml",
            credential_profiles=normalized / "credentials.yaml",
            host_trust=normalized / "known-hosts.yaml",
            history=normalized / "history.sqlite3",
        )

    @classmethod
    def default(cls) -> "StatePaths":
        return cls.from_root(default_state_directory())
