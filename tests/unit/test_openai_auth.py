import pytest
from keyring.errors import PasswordDeleteError
from pydantic import SecretStr

from netsage.ai.providers.openai import KeyringOpenAIAPIKeyStore, OpenAINotAuthenticatedError
from netsage.ai.providers.openai import auth as auth_module

API_KEY_CANARY = "sk-synthetic-keyring-canary"


def test_openai_api_key_uses_separate_keyring_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values: dict[tuple[str, str], str] = {}
    monkeypatch.setattr(
        auth_module.keyring,
        "get_keyring",
        lambda: type("Backend", (), {"priority": 1})(),
    )
    monkeypatch.setattr(
        auth_module.keyring,
        "set_password",
        lambda service, account, value: values.__setitem__((service, account), value),
    )
    monkeypatch.setattr(
        auth_module.keyring,
        "get_password",
        lambda service, account: values.get((service, account)),
    )

    def delete(service: str, account: str) -> None:
        try:
            del values[(service, account)]
        except KeyError as error:
            raise PasswordDeleteError("missing") from error

    monkeypatch.setattr(auth_module.keyring, "delete_password", delete)
    store = KeyringOpenAIAPIKeyStore()

    store.set_api_key(SecretStr(API_KEY_CANARY))
    resolved = store.get_api_key()

    assert store.has_api_key() is True
    assert API_KEY_CANARY not in repr(resolved)
    assert values[("NetSage OpenAI Provider", "api-key")] == API_KEY_CANARY
    assert ("NetSage", "api-key") not in values

    store.delete_api_key()
    assert store.has_api_key() is False
    with pytest.raises(OpenAINotAuthenticatedError):
        store.get_api_key()
