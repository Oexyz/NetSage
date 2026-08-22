from pathlib import Path

import pytest
from pydantic import SecretStr
from typer.testing import CliRunner

from netsage.ai.providers.codex import CodexAccountState, CodexStructuredOutput
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OpenAIAuthStoreError,
    OpenAIModel,
    OpenAIStructuredOutput,
)
from netsage.ai.providers.openai_codex import (
    CodexOAuthStatus,
    CodexOAuthTokenState,
)
from netsage.cli import ai_commands
from netsage.cli.main import app
from netsage.state import LocalState, StatePaths

runner = CliRunner()
API_KEY_CANARY = "sk-synthetic-cli-canary"


class FakeOpenAIClient:
    def __init__(self) -> None:
        self.keys: list[SecretStr] = []

    async def list_models(self, api_key: SecretStr) -> tuple[OpenAIModel, ...]:
        self.keys.append(api_key)
        return (OpenAIModel(id="gpt-5.6-terra", owned_by="openai"),)

    async def complete_structured(
        self, *_args: object, **_kwargs: object
    ) -> OpenAIStructuredOutput:
        raise AssertionError("CLI metadata tests must not run a model response")


class FakeCodexStatusClient:
    def __init__(self, *, installed: bool, authenticated: bool) -> None:
        self._installed = installed
        self.authenticated = authenticated
        self.closed = False

    @property
    def installed(self) -> bool:
        return self._installed

    async def account_state(self) -> CodexAccountState:
        return CodexAccountState(
            installed=self.installed,
            authenticated=self.authenticated if self.installed else False,
            auth_mode="chatgpt" if self.installed and self.authenticated else None,
            plan_type="plus" if self.installed and self.authenticated else None,
        )

    async def complete_structured(self, *_args: object, **_kwargs: object) -> CodexStructuredOutput:
        raise AssertionError("status must not run a model response")

    async def close(self) -> None:
        self.closed = True


def isolated_state(tmp_path: Path) -> LocalState:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    return state


class UnconfiguredOAuthManager:
    @property
    def configured(self) -> bool:
        return False

    def status(self) -> CodexOAuthStatus:
        return CodexOAuthStatus(
            configured=False,
            authenticated=False,
            token_state=CodexOAuthTokenState.NOT_CONFIGURED,
        )


def test_openai_first_start_login_status_models_logout_and_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    keys = InMemoryOpenAIAPIKeyStore()
    client = FakeOpenAIClient()
    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_api_keys", lambda: keys)
    monkeypatch.setattr(ai_commands, "_client", lambda: client)
    monkeypatch.setattr(ai_commands.webbrowser, "open", lambda _url: True)

    before = runner.invoke(app, ["ai", "openai", "status"])
    login = runner.invoke(
        app,
        ["ai", "openai", "login"],
        input=f"{API_KEY_CANARY}\n",
    )
    after = runner.invoke(app, ["ai", "openai", "status"])
    models = runner.invoke(app, ["ai", "openai", "models"])
    configured = runner.invoke(
        app,
        ["ai", "openai", "configure", "--model", "gpt-5.6-terra", "--effort", "high"],
    )
    logout = runner.invoke(app, ["ai", "openai", "logout"])

    for result in (before, login, after, models, configured, logout):
        assert result.exit_code == 0, result.stdout
    assert "NOT AUTHENTICATED" in before.stdout
    assert "OpenAI authentication verified" in login.stdout
    assert "usage-based OpenAI API provider" in login.stdout
    assert "API key in OS credential store" in after.stdout
    assert "gpt-5.6-terra" in models.stdout
    assert API_KEY_CANARY not in "".join(
        result.stdout for result in (before, login, after, models, configured, logout)
    )
    assert state.settings.load().ai.openai.reasoning_effort == "high"
    for path in state.paths.root.iterdir():
        assert API_KEY_CANARY.encode() not in path.read_bytes()
    assert keys.has_api_key() is False


def test_openai_models_requires_login(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_api_keys", InMemoryOpenAIAPIKeyStore)
    monkeypatch.setattr(ai_commands, "_client", FakeOpenAIClient)

    result = runner.invoke(app, ["ai", "openai", "models"])

    assert result.exit_code == 1
    assert "OPENAI_NOT_AUTHENTICATED" in result.stdout


def test_openai_status_reports_unavailable_keyring_without_crashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)

    class UnavailableStore(InMemoryOpenAIAPIKeyStore):
        def get_api_key(self) -> SecretStr:
            raise OpenAIAuthStoreError("synthetic unavailable")

    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_api_keys", UnavailableStore)
    monkeypatch.setattr(ai_commands, "_client", FakeOpenAIClient)

    result = runner.invoke(app, ["ai", "openai", "status"])

    assert result.exit_code == 0
    assert "UNAVAILABLE" in result.stdout
    assert "synthetic" not in result.stdout


def test_ai_status_selects_authenticated_installed_codex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex = FakeCodexStatusClient(installed=True, authenticated=True)
    monkeypatch.setattr(ai_commands, "_codex_client", lambda: codex)
    monkeypatch.setattr(ai_commands, "_codex_oauth_manager", UnconfiguredOAuthManager)
    monkeypatch.setattr(ai_commands, "_api_keys", InMemoryOpenAIAPIKeyStore)

    result = runner.invoke(app, ["ai", "status"])

    assert result.exit_code == 0
    assert "Codex App Server" in result.stdout
    assert "ChatGPT managed (plus)" in result.stdout
    assert "OpenAI API" in result.stdout
    assert codex.closed is True


def test_ai_status_selects_api_only_when_codex_is_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    codex = FakeCodexStatusClient(installed=False, authenticated=False)
    monkeypatch.setattr(ai_commands, "_codex_client", lambda: codex)
    monkeypatch.setattr(ai_commands, "_codex_oauth_manager", UnconfiguredOAuthManager)
    monkeypatch.setattr(
        ai_commands,
        "_api_keys",
        lambda: InMemoryOpenAIAPIKeyStore(API_KEY_CANARY),
    )

    result = runner.invoke(app, ["ai", "status"])

    assert result.exit_code == 0
    assert "OpenAI API" in result.stdout
    assert "ABSENT" in result.stdout
    assert "READY" in result.stdout


def test_ai_and_ask_help_describe_separate_provider_routes() -> None:
    ai_help = runner.invoke(app, ["ai", "--help"])
    provider_help = runner.invoke(app, ["ai", "openai", "--help"])
    ask_help = runner.invoke(app, ["ask", "--help"])

    assert ai_help.exit_code == 0
    assert provider_help.exit_code == 0
    assert ask_help.exit_code == 0
    combined = ai_help.stdout + provider_help.stdout + ask_help.stdout
    assert "OpenAI" in combined
    assert "Codex" in combined
    assert "usage-based" in combined
