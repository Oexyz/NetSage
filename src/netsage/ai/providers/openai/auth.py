"""Separate OS-keyring storage for the OpenAI provider API key."""

from typing import Protocol

import keyring
from keyring.errors import PasswordDeleteError
from pydantic import SecretStr

OPENAI_KEYRING_SERVICE = "NetSage OpenAI Provider"
OPENAI_KEYRING_ACCOUNT = "api-key"


class OpenAIAuthStoreError(RuntimeError):
    """Safe provider-auth storage failure without key material."""


class OpenAINotAuthenticatedError(OpenAIAuthStoreError):
    pass


class OpenAIAPIKeyStore(Protocol):
    def set_api_key(self, api_key: SecretStr) -> None: ...

    def get_api_key(self) -> SecretStr: ...

    def delete_api_key(self, *, missing_ok: bool = False) -> None: ...

    def has_api_key(self) -> bool: ...


class KeyringOpenAIAPIKeyStore(OpenAIAPIKeyStore):
    """Use a provider-specific keyring namespace, never device credential metadata."""

    @staticmethod
    def ensure_available() -> None:
        try:
            backend = keyring.get_keyring()
            priority = backend.priority
        except Exception as error:
            raise OpenAIAuthStoreError("Secure OS credential storage is unavailable") from error
        if priority <= 0:
            raise OpenAIAuthStoreError("Secure OS credential storage is unavailable")

    def set_api_key(self, api_key: SecretStr) -> None:
        value = api_key.get_secret_value()
        if not value:
            raise ValueError("OpenAI API key must not be empty")
        self.ensure_available()
        try:
            keyring.set_password(OPENAI_KEYRING_SERVICE, OPENAI_KEYRING_ACCOUNT, value)
        except Exception as error:
            raise OpenAIAuthStoreError("Unable to store OpenAI API key securely") from error

    def get_api_key(self) -> SecretStr:
        self.ensure_available()
        try:
            value = keyring.get_password(OPENAI_KEYRING_SERVICE, OPENAI_KEYRING_ACCOUNT)
        except Exception as error:
            raise OpenAIAuthStoreError("Unable to read OpenAI authentication securely") from error
        if value is None:
            raise OpenAINotAuthenticatedError("OpenAI is not authenticated")
        return SecretStr(value)

    def delete_api_key(self, *, missing_ok: bool = False) -> None:
        self.ensure_available()
        try:
            keyring.delete_password(OPENAI_KEYRING_SERVICE, OPENAI_KEYRING_ACCOUNT)
        except PasswordDeleteError as error:
            if not missing_ok:
                raise OpenAINotAuthenticatedError("OpenAI is not authenticated") from error
        except Exception as error:
            raise OpenAIAuthStoreError("Unable to remove OpenAI authentication") from error

    def has_api_key(self) -> bool:
        try:
            self.get_api_key()
        except OpenAINotAuthenticatedError:
            return False
        return True


class InMemoryOpenAIAPIKeyStore(OpenAIAPIKeyStore):
    """Deterministic secret store for tests; never selected by production composition."""

    def __init__(self, api_key: str | None = None) -> None:
        self._api_key = SecretStr(api_key) if api_key is not None else None

    def set_api_key(self, api_key: SecretStr) -> None:
        self._api_key = api_key

    def get_api_key(self) -> SecretStr:
        if self._api_key is None:
            raise OpenAINotAuthenticatedError("OpenAI is not authenticated")
        return self._api_key

    def delete_api_key(self, *, missing_ok: bool = False) -> None:
        if self._api_key is None and not missing_ok:
            raise OpenAINotAuthenticatedError("OpenAI is not authenticated")
        self._api_key = None

    def has_api_key(self) -> bool:
        return self._api_key is not None
