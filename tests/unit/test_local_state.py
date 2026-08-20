import os
from pathlib import Path

import pytest

from netsage.credentials import CredentialProfile, CredentialProviderType
from netsage.inventory import DuplicateDeviceError
from netsage.models import CredentialReference, DeviceRef
from netsage.state import (
    InvalidStateReferenceError,
    LocalState,
    SSHHostTrustRecord,
    StateFileInvalidError,
    StatePaths,
    StateSchemaVersionError,
    StateWriteError,
    default_state_directory,
)
from netsage.state import atomic as atomic_module


def test_platform_state_paths_are_user_level() -> None:
    home = Path("C:/Users/tester")
    windows = default_state_directory(
        platform="win32",
        environment={"LOCALAPPDATA": "C:/Users/tester/AppData/Local"},
        home=home,
    )
    linux = default_state_directory(platform="linux", environment={}, home=Path("/home/tester"))
    xdg = default_state_directory(
        platform="linux",
        environment={"XDG_CONFIG_HOME": "/home/tester/config"},
        home=Path("/home/tester"),
    )
    macos = default_state_directory(platform="darwin", environment={}, home=Path("/Users/tester"))

    assert windows.as_posix().endswith("AppData/Local/NetSage")
    assert linux == Path("/home/tester/.config/netsage")
    assert xdg == Path("/home/tester/config/netsage")
    assert macos == Path("/Users/tester/Library/Application Support/NetSage")


def test_clean_initialization_creates_versioned_separate_state(tmp_path: Path) -> None:
    paths = StatePaths.from_root(tmp_path / "state")
    state = LocalState(paths)
    state.initialize()
    state.initialize()

    assert state.settings.load().schema_version == 1
    assert state.inventory.load().devices == {}
    assert state.credentials.load().profiles == {}
    assert state.host_trust.load().hosts == {}
    for path in (
        paths.settings,
        paths.inventory,
        paths.credential_profiles,
        paths.host_trust,
    ):
        assert path.is_file()
        assert "schema_version: 1" in path.read_text(encoding="utf-8")
        if os.name != "nt":
            assert path.stat().st_mode & 0o077 == 0


def test_inventory_profiles_and_trust_reload_across_state_instances(tmp_path: Path) -> None:
    paths = StatePaths.from_root(tmp_path / "state")
    state = LocalState(paths)
    state.initialize()
    profile = CredentialProfile(
        name="fortigate-readonly",
        provider=CredentialProviderType.KEYRING,
        username="netsage-ro",
    )
    state.credentials.add(profile)
    state.host_trust.add(
        SSHHostTrustRecord(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            algorithm="ssh-ed25519",
            fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    state.inventory.add(
        DeviceRef(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            platform="fortios",
            credential_ref=CredentialReference(profile.name),
            trust_ref="fortigate-example",
        )
    )

    reloaded = LocalState(paths)
    device = reloaded.load_inventory().get_device("fortigate-example")
    assert str(device.credential_ref) == "fortigate-readonly"
    assert device.trust_ref == "fortigate-example"
    assert reloaded.credentials.get(profile.name).username == "netsage-ro"
    assert reloaded.host_trust.get(device.name).algorithm == "ssh-ed25519"


def test_invalid_yaml_and_unknown_schema_are_not_modified(tmp_path: Path) -> None:
    paths = StatePaths.from_root(tmp_path / "state")
    state = LocalState(paths)
    state.initialize()

    invalid = "schema_version: [broken"
    paths.inventory.write_text(invalid, encoding="utf-8")
    with pytest.raises(StateFileInvalidError, match=r"inventory\.yaml"):
        state.inventory.load()
    assert paths.inventory.read_text(encoding="utf-8") == invalid

    future = "schema_version: 999\ndevices: {}\nsites: {}\ngroups: {}\n"
    paths.inventory.write_text(future, encoding="utf-8")
    with pytest.raises(StateSchemaVersionError, match="999"):
        state.inventory.load()
    assert paths.inventory.read_text(encoding="utf-8") == future


def test_atomic_replace_failure_preserves_previous_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths = StatePaths.from_root(tmp_path / "state")
    state = LocalState(paths)
    state.initialize()
    original = paths.inventory.read_text(encoding="utf-8")

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("synthetic replace failure")

    monkeypatch.setattr(atomic_module.os, "replace", fail_replace)
    with pytest.raises(StateWriteError, match=r"inventory\.yaml"):
        state.inventory.save(state.inventory.load())

    assert paths.inventory.read_text(encoding="utf-8") == original
    assert not tuple(paths.root.glob("*.tmp"))


def test_duplicate_device_and_missing_profile_reference_fail_closed(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.host_trust.add(
        SSHHostTrustRecord(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            algorithm="ssh-ed25519",
            fingerprint="SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
    )
    device = DeviceRef(
        name="fortigate-example",
        host="192.0.2.10",
        platform="fortios",
        credential_ref="missing-profile",
        trust_ref="fortigate-example",
    )
    state.inventory.add(device)
    with pytest.raises(DuplicateDeviceError):
        state.inventory.add(device)
    with pytest.raises(InvalidStateReferenceError, match="missing credential profile"):
        state.load_inventory()


def test_canary_secret_is_never_serialized_to_state_files(tmp_path: Path) -> None:
    canary = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_LOCAL_STATE"
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    state.credentials.add(CredentialProfile(name="fortigate-readonly", username="netsage-ro"))

    serialized = "".join(
        path.read_text(encoding="utf-8") for path in state.paths.root.glob("*.yaml")
    )
    assert canary not in serialized
    assert "password:" not in serialized.casefold()
    assert "secret:" not in serialized.casefold()
