from pathlib import Path

import pytest
from keyring.errors import PasswordDeleteError

from netsage.credentials import (
    KEYRING_SERVICE_NAME,
    CredentialKind,
    CredentialProfileInUseError,
    CredentialProfileService,
    CredentialSecretStore,
    CredentialSecretUnavailableError,
    CredentialStoreError,
    CredentialTransactionError,
    DuplicateCredentialProfileError,
    KeyringCredentialProvider,
    KeyringSecretStore,
    SecureCredentialStoreUnavailableError,
)
from netsage.credentials import keyring_provider as keyring_module
from netsage.models import DeviceRef
from netsage.state import LocalState, StatePaths


class MemorySecretStore(CredentialSecretStore):
    def __init__(self) -> None:
        self.values: dict[str, str] = {}
        self.fail_set = False
        self.fail_delete = False

    def set_secret(self, profile_name: str, secret: str) -> None:
        if self.fail_set:
            raise CredentialStoreError("synthetic backend failure")
        self.values[profile_name] = secret

    def get_secret(self, profile_name: str) -> str:
        try:
            return self.values[profile_name]
        except KeyError as error:
            raise CredentialSecretUnavailableError("Credential secret unavailable") from error

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        if self.fail_delete:
            raise CredentialStoreError("synthetic backend failure")
        if profile_name not in self.values and not missing_ok:
            raise CredentialSecretUnavailableError("Credential secret unavailable")
        self.values.pop(profile_name, None)


class UsableBackend:
    priority = 1
    name = "SyntheticKeyring"


def patch_keyring(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[tuple[str, str], str],
) -> None:
    monkeypatch.setattr(keyring_module.keyring, "get_keyring", lambda: UsableBackend())
    monkeypatch.setattr(
        keyring_module.keyring,
        "set_password",
        lambda service, name, secret: values.__setitem__((service, name), secret),
    )
    monkeypatch.setattr(
        keyring_module.keyring,
        "get_password",
        lambda service, name: values.get((service, name)),
    )

    def delete(service: str, name: str) -> None:
        try:
            del values[(service, name)]
        except KeyError as error:
            raise PasswordDeleteError("missing") from error

    monkeypatch.setattr(keyring_module.keyring, "delete_password", delete)


def test_keyring_secret_store_add_resolve_delete_and_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_KEYRING"
    values: dict[tuple[str, str], str] = {}
    patch_keyring(monkeypatch, values)
    store = KeyringSecretStore()

    store.set_secret("fortigate-readonly", canary)
    assert values[(KEYRING_SERVICE_NAME, "fortigate-readonly")] == canary
    assert store.get_secret("fortigate-readonly") == canary
    store.delete_secret("fortigate-readonly")
    with pytest.raises(CredentialSecretUnavailableError, match="unavailable") as captured:
        store.get_secret("fortigate-readonly")
    assert canary not in str(captured.value)


def test_keyring_backend_failure_is_fail_closed_without_plaintext_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unavailable() -> UsableBackend:
        raise RuntimeError("synthetic unavailable backend")

    monkeypatch.setattr(keyring_module.keyring, "get_keyring", unavailable)
    store = KeyringSecretStore()
    with pytest.raises(SecureCredentialStoreUnavailableError, match="unavailable"):
        store.set_secret("fortigate-readonly", "not-persisted")


@pytest.mark.asyncio
async def test_keyring_provider_combines_metadata_and_secret_only_at_runtime(
    tmp_path: Path,
) -> None:
    canary = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_PROVIDER"
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )
    service.add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret=canary,
    )

    credential = await KeyringCredentialProvider(state.credentials, secrets).resolve(
        "fortigate-readonly"
    )
    assert credential.username == "netsage-ro"
    assert credential.kind is CredentialKind.PASSWORD
    assert credential.secret == canary
    assert canary not in repr(credential)
    assert canary not in state.paths.credential_profiles.read_text(encoding="utf-8")


def test_credential_add_rolls_back_secret_when_metadata_write_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_ROLLBACK"
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )

    def fail_add(_profile: object) -> None:
        raise OSError("synthetic metadata failure")

    monkeypatch.setattr(state.credentials, "add", fail_add)
    with pytest.raises(CredentialTransactionError, match="could not be saved") as captured:
        service.add_password_profile(
            name="fortigate-readonly",
            username="netsage-ro",
            secret=canary,
        )
    assert secrets.values == {}
    assert canary not in str(captured.value)


def test_duplicate_profile_does_not_overwrite_existing_secret(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )
    service.add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret="original" + "-secret",
    )
    with pytest.raises(DuplicateCredentialProfileError):
        service.add_password_profile(
            name="fortigate-readonly",
            username="different-user",
            secret="replacement" + "-secret",
        )
    assert secrets.values["fortigate-readonly"] == "original-secret"


def test_credential_remove_rejects_references_and_does_not_remove_shared_secret(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )
    service.add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret="synthetic" + "-secret",
    )
    state.inventory.add(
        DeviceRef(
            name="fortigate-example",
            host="192.0.2.10",
            platform="fortios",
            credential_ref="fortigate-readonly",
            trust_ref="fortigate-example",
        )
    )

    with pytest.raises(CredentialProfileInUseError, match="fortigate-example"):
        service.remove_profile("fortigate-readonly")
    assert "fortigate-readonly" in secrets.values


def test_unreferenced_credential_remove_deletes_metadata_and_secret(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )
    service.add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret="synthetic" + "-secret",
    )
    service.remove_profile("fortigate-readonly")
    assert state.credentials.load().profiles == {}
    assert secrets.values == {}


def test_referenced_profile_secret_rotation_preserves_metadata_and_replaces_value(
    tmp_path: Path,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    service = CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    )
    service.add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret="old" + "-secret",
    )
    metadata_before = state.paths.credential_profiles.read_bytes()
    service.rotate_secret("fortigate-readonly", "new" + "-secret")

    assert secrets.values["fortigate-readonly"] == "new-secret"
    assert state.paths.credential_profiles.read_bytes() == metadata_before
    serialized = "".join(
        path.read_text(encoding="utf-8") for path in state.paths.root.glob("*.yaml")
    )
    assert "old-secret" not in serialized
    assert "new-secret" not in serialized
