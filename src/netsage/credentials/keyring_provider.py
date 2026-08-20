"""OS-keyring password storage and trusted credential resolution."""

from typing import Protocol

import keyring
from keyring.errors import PasswordDeleteError

from netsage.credentials.core import Credential, CredentialKind, CredentialProvider
from netsage.credentials.profiles import (
    CredentialProfile,
    CredentialProfileInUseError,
    CredentialProfileStore,
    CredentialProviderType,
    DuplicateCredentialProfileError,
)
from netsage.inventory.store import InventoryStore

KEYRING_SERVICE_NAME = "NetSage"


class CredentialStoreError(RuntimeError):
    """Safe credential-store error which never includes secret material."""


class SecureCredentialStoreUnavailableError(CredentialStoreError):
    pass


class CredentialSecretUnavailableError(CredentialStoreError):
    pass


class CredentialTransactionError(CredentialStoreError):
    pass


class CredentialSecretStore(Protocol):
    def set_secret(self, profile_name: str, secret: str) -> None: ...

    def get_secret(self, profile_name: str) -> str: ...

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None: ...


class KeyringSecretStore:
    """Store only password material in the operating-system credential backend."""

    def __init__(self, *, service_name: str = KEYRING_SERVICE_NAME) -> None:
        self._service_name = service_name

    @property
    def service_name(self) -> str:
        return self._service_name

    @staticmethod
    def ensure_available() -> None:
        try:
            backend = keyring.get_keyring()
            priority = backend.priority
        except Exception as error:
            raise SecureCredentialStoreUnavailableError(
                "Secure OS credential storage is unavailable"
            ) from error
        if priority <= 0:
            raise SecureCredentialStoreUnavailableError(
                "Secure OS credential storage is unavailable"
            )

    def set_secret(self, profile_name: str, secret: str) -> None:
        if not secret:
            raise ValueError("credential secret must not be empty")
        self.ensure_available()
        try:
            keyring.set_password(self._service_name, profile_name, secret)
        except Exception as error:
            raise CredentialStoreError("Unable to store credential securely") from error

    def get_secret(self, profile_name: str) -> str:
        self.ensure_available()
        try:
            secret = keyring.get_password(self._service_name, profile_name)
        except Exception as error:
            raise CredentialStoreError("Unable to read credential securely") from error
        if secret is None:
            raise CredentialSecretUnavailableError("Credential secret unavailable")
        return secret

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        self.ensure_available()
        try:
            keyring.delete_password(self._service_name, profile_name)
        except PasswordDeleteError as error:
            if not missing_ok:
                raise CredentialSecretUnavailableError("Credential secret unavailable") from error
        except Exception as error:
            raise CredentialStoreError("Unable to delete credential securely") from error


class KeyringCredentialProvider(CredentialProvider):
    """Resolve profile metadata plus its OS-keyring password inside the trusted boundary."""

    def __init__(
        self,
        profile_store: CredentialProfileStore,
        secret_store: CredentialSecretStore | None = None,
    ) -> None:
        self._profile_store = profile_store
        self._secret_store = secret_store or KeyringSecretStore()

    async def resolve(self, credential_ref: str) -> Credential:
        profile = self._profile_store.get(credential_ref)
        if profile.provider is not CredentialProviderType.KEYRING:
            raise CredentialStoreError("Credential profile provider is unsupported")
        if profile.kind is not CredentialKind.PASSWORD:
            raise CredentialStoreError("Credential profile kind is unsupported")
        secret = self._secret_store.get_secret(profile.name)
        return Credential(username=profile.username, secret=secret, kind=profile.kind)


class CredentialProfileService:
    """Coordinate keyring and metadata changes with rollback and reference checks."""

    def __init__(
        self,
        *,
        profiles: CredentialProfileStore,
        secrets: CredentialSecretStore,
        inventory: InventoryStore,
    ) -> None:
        self._profiles = profiles
        self._secrets = secrets
        self._inventory = inventory

    def add_password_profile(self, *, name: str, username: str, secret: str) -> CredentialProfile:
        profile = CredentialProfile(name=name, username=username)
        if name in self._profiles.load().profiles:
            raise DuplicateCredentialProfileError(f"Credential profile already exists: {name}")
        self._secrets.set_secret(name, secret)
        try:
            self._profiles.add(profile)
        except Exception as error:
            try:
                self._secrets.delete_secret(name, missing_ok=True)
            except Exception as rollback_error:
                raise CredentialTransactionError(
                    "Credential metadata failed and secure rollback was unsuccessful"
                ) from rollback_error
            raise CredentialTransactionError("Credential metadata could not be saved") from error
        return profile

    def remove_profile(self, name: str) -> None:
        profile = self._profiles.get(name)
        references = tuple(
            device.name
            for device in self._inventory.load().devices.values()
            if str(device.credential_ref) == name
        )
        if references:
            raise CredentialProfileInUseError(
                f"Credential profile is referenced by device: {references[0]}"
            )
        self._profiles.remove(name)
        try:
            self._secrets.delete_secret(name, missing_ok=True)
        except Exception as error:
            try:
                self._profiles.add(profile)
            except Exception as rollback_error:
                raise CredentialTransactionError(
                    "Credential removal failed and metadata rollback was unsuccessful"
                ) from rollback_error
            raise CredentialTransactionError("Credential secret could not be removed") from error
