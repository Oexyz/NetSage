import base64
import json
from datetime import UTC, datetime, timedelta
from io import StringIO
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import SecretStr
from rich.console import Console
from typer.testing import CliRunner

from netsage.agent import AgentInvestigationReport, AgentRuntimeState
from netsage.ai.providers.codex import CodexAccountState, CodexStructuredOutput
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OpenAIModel,
    OpenAIServiceClient,
    OpenAIStructuredOutput,
)
from netsage.ai.providers.openai_codex import (
    CodexDeviceAuthorization,
    CodexOAuthProvider,
    CodexOAuthTokenBundle,
    CodexOAuthTokenManager,
    InMemoryCodexOAuthTokenStore,
)
from netsage.cli import ai_commands
from netsage.cli import shell as shell_module
from netsage.cli.main import app
from netsage.cli.shell import NetSageInteractiveShell
from netsage.state import LocalState, StatePaths

runner = CliRunner()
NOW = datetime(2026, 8, 22, 13, 0, tzinfo=UTC)
ACCESS_TOKEN_CANARY = "codex-oauth-access-token-canary"  # noqa: S105 - synthetic canary
REFRESH_TOKEN_CANARY = "codex-oauth-refresh-token-canary"  # noqa: S105 - synthetic canary
ID_TOKEN_CANARY = "codex-oauth-id-token-canary"  # noqa: S105 - synthetic canary


def jwt(*, expires_at: datetime, marker: str) -> str:
    def encode(value: object) -> str:
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    payload = {
        "exp": int(expires_at.timestamp()),
        "marker": marker,
        "https://api.openai.com/auth": {
            "chatgpt_account_id": "account-synthetic",
            "chatgpt_plan_type": "plus",
        },
    }
    return f"{encode({'alg': 'none'})}.{encode(payload)}.c2ln"


def token_bundle() -> CodexOAuthTokenBundle:
    return CodexOAuthTokenBundle(
        access_token=SecretStr(
            jwt(expires_at=NOW + timedelta(hours=1), marker=ACCESS_TOKEN_CANARY)
        ),
        refresh_token=SecretStr(REFRESH_TOKEN_CANARY),
        id_token=SecretStr(jwt(expires_at=NOW + timedelta(hours=1), marker=ID_TOKEN_CANARY)),
        obtained_at=NOW,
    )


class FakeOAuthProtocol:
    def __init__(self) -> None:
        self.requested = 0
        self.completed = 0

    async def request_device_authorization(self) -> CodexDeviceAuthorization:
        self.requested += 1
        return CodexDeviceAuthorization(
            verification_url="https://auth.example.invalid/codex/device",
            user_code=SecretStr("ABCD-EFGH"),
            device_auth_id=SecretStr("device-auth-secret-canary"),
            interval_seconds=1,
            expires_at=NOW + timedelta(minutes=15),
        )

    async def complete_device_authorization(
        self,
        _authorization: CodexDeviceAuthorization,
    ) -> CodexOAuthTokenBundle:
        self.completed += 1
        return token_bundle()

    async def refresh_tokens(
        self,
        tokens: CodexOAuthTokenBundle,
    ) -> CodexOAuthTokenBundle:
        return tokens


def isolated_state(tmp_path: Path) -> LocalState:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    return state


def test_native_login_status_logout_work_without_codex_or_api_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    store = InMemoryCodexOAuthTokenStore()
    protocol = FakeOAuthProtocol()
    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_codex_oauth_store", lambda: store)
    monkeypatch.setattr(ai_commands, "_codex_oauth_http_client", lambda: protocol)
    monkeypatch.setattr(
        ai_commands,
        "_codex_oauth_manager",
        lambda *_args, **_kwargs: CodexOAuthTokenManager(
            store=store,
            refresh_client=protocol,
            clock=lambda: NOW,
        ),
    )
    monkeypatch.setattr(
        ai_commands,
        "_codex_client",
        lambda: (_ for _ in ()).throw(AssertionError("Codex CLI must not be used")),
    )
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "absent-codex-home"))
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    login = runner.invoke(app, ["ai", "codex", "login", "--no-browser"])
    status = runner.invoke(app, ["ai", "codex", "status"])
    logout = runner.invoke(app, ["ai", "codex", "logout"])

    for result in (login, status, logout):
        assert result.exit_code == 0, result.stdout
    assert "ABCD-EFGH" in login.stdout
    assert "Authentication successful" in login.stdout
    assert "VALID" in status.stdout
    assert "EXPERIMENTAL" in status.stdout
    assert "browser sessions were not changed" in logout.stdout
    assert protocol.requested == 1
    assert protocol.completed == 1
    assert store.configured() is False
    assert state.settings.load().ai.provider == "openai-codex"
    serialized_state = b"".join(path.read_bytes() for path in state.paths.root.iterdir())
    combined_output = login.stdout + status.stdout + logout.stdout
    for canary in (
        token_bundle().access_token.get_secret_value(),
        REFRESH_TOKEN_CANARY,
        token_bundle().id_token.get_secret_value(),
        "device-auth-secret-canary",
    ):
        assert canary not in serialized_state.decode(errors="ignore")
        assert canary not in combined_output


def test_codex_status_uses_same_handler_inside_repl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    store = InMemoryCodexOAuthTokenStore(token_bundle())
    protocol = FakeOAuthProtocol()
    manager = CodexOAuthTokenManager(
        store=store,
        refresh_client=protocol,
        clock=lambda: NOW,
    )
    monkeypatch.setattr(ai_commands, "_codex_oauth_manager", lambda: manager)
    monkeypatch.setattr(shell_module.StatePaths, "default", lambda: state.paths)
    inputs = iter(("ai codex status", "exit"))
    output = StringIO()
    repl_console = Console(file=output, force_terminal=False, color_system=None)
    monkeypatch.setattr(ai_commands, "console", repl_console)
    shell = NetSageInteractiveShell(
        app,
        input_reader=lambda _prompt: next(inputs),
        console=repl_console,
    )

    shell.run()

    rendered = output.getvalue()
    assert "OpenAI Codex OAuth status" in rendered
    assert "VALID" in rendered
    assert REFRESH_TOKEN_CANARY not in rendered


def test_existing_auth_import_requires_explicit_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DeclineImporter:
        def __init__(self, _store: object) -> None:
            pass

        def detected(self) -> bool:
            return True

        def import_file(self) -> None:
            raise AssertionError("declined import must not read source credentials")

    monkeypatch.setattr(ai_commands, "CodexExistingAuthImporter", DeclineImporter)
    monkeypatch.setattr(ai_commands, "_codex_oauth_store", InMemoryCodexOAuthTokenStore)

    result = runner.invoke(app, ["ai", "codex", "import-existing"], input="n\n")

    assert result.exit_code == 0
    assert "source was not read or modified" in result.stdout


def test_provider_choice_is_non_secret_yaml_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    monkeypatch.setattr(ai_commands, "_state", lambda: state)

    result = runner.invoke(
        app,
        ["ai", "configure", "--provider", "openai-api"],
    )

    assert result.exit_code == 0
    assert state.settings.load().ai.provider == "openai-api"
    assert "token" not in state.paths.settings.read_text(encoding="utf-8").casefold()


def test_login_keyboard_interrupt_cancels_without_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    store = InMemoryCodexOAuthTokenStore()

    class CancelProtocol(FakeOAuthProtocol):
        async def complete_device_authorization(
            self,
            _authorization: CodexDeviceAuthorization,
        ) -> CodexOAuthTokenBundle:
            raise KeyboardInterrupt

    protocol = CancelProtocol()
    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_codex_oauth_store", lambda: store)
    monkeypatch.setattr(ai_commands, "_codex_oauth_http_client", lambda: protocol)

    result = runner.invoke(app, ["ai", "codex", "login", "--no-browser"])

    assert result.exit_code == 130
    assert "cancelled" in result.stdout
    assert store.configured() is False


def test_codex_help_has_no_token_reveal_or_export_surface() -> None:
    result = runner.invoke(app, ["ai", "codex", "--help"])

    assert result.exit_code == 0
    for command in ("login", "status", "logout", "import-existing"):
        assert command in result.stdout
    for forbidden in ("export-token", "reveal", " token "):
        assert forbidden not in result.stdout.casefold()


def test_ask_composition_selects_native_oauth_without_app_server_or_api(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = isolated_state(tmp_path)
    store = InMemoryCodexOAuthTokenStore(token_bundle())
    protocol = FakeOAuthProtocol()

    class NoInference:
        async def complete_structured(self, *_args: object, **_kwargs: object) -> object:
            raise AssertionError("fake ask service must own the synthetic report")

    oauth_provider = CodexOAuthProvider(
        state.settings.load().ai.openai,
        tokens=CodexOAuthTokenManager(
            store=store,
            refresh_client=protocol,
            clock=lambda: NOW,
        ),
        client=NoInference(),  # type: ignore[arg-type]
    )

    class AbsentCodex:
        installed = False

        async def account_state(self) -> CodexAccountState:
            return CodexAccountState(installed=False, authenticated=False)

        async def complete_structured(
            self, *_args: object, **_kwargs: object
        ) -> CodexStructuredOutput:
            raise AssertionError

        async def close(self) -> None:
            return None

    class NeverOpenAI(OpenAIServiceClient):
        async def list_models(self, _api_key: SecretStr) -> tuple[OpenAIModel, ...]:
            raise AssertionError("API billing path must not be selected")

        async def complete_structured(
            self, *_args: object, **_kwargs: object
        ) -> OpenAIStructuredOutput:
            raise AssertionError("API billing path must not be selected")

    class FakeAskService:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["provider"] is oauth_provider
            assert kwargs["provider_name"] == "openai-codex"

        async def ask(self, device_id: str, _question: str) -> AgentInvestigationReport:
            return AgentInvestigationReport(
                investigation_id=UUID(int=1),
                device_id=device_id,
                provider="openai-codex",
                state=AgentRuntimeState.COMPLETED,
                deterministic_findings=(),
                ai_assessment={
                    "response_type": "final",
                    "summary": "Synthetic OAuth result.",
                    "diagnosis_strength": "insufficient",
                },
            )

    monkeypatch.setattr(ai_commands, "_state", lambda: state)
    monkeypatch.setattr(ai_commands, "_codex_oauth_provider", lambda _settings: oauth_provider)
    monkeypatch.setattr(ai_commands, "_codex_client", AbsentCodex)
    monkeypatch.setattr(ai_commands, "_api_keys", InMemoryOpenAIAPIKeyStore)
    monkeypatch.setattr(ai_commands, "_client", NeverOpenAI)
    monkeypatch.setattr(ai_commands, "FortiOSAIInvestigationService", FakeAskService)

    result = runner.invoke(app, ["ask", "fortigate-example", "Check routing."])

    assert result.exit_code == 0, result.stdout
    assert "openai-codex" in result.stdout
    assert REFRESH_TOKEN_CANARY not in result.stdout
