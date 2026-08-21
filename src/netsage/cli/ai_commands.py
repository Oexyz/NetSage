"""Codex-first OpenAI runtime selection, API fallback, and ask CLI."""

import asyncio
import webbrowser
from dataclasses import dataclass

import typer
from pydantic import SecretStr, TypeAdapter
from rich.console import Console
from rich.table import Table

from netsage.agent import (
    AgentRuntimeState,
    FortiOSAIInvestigationService,
    render_agent_report,
)
from netsage.ai import AIProviderError
from netsage.ai.providers.codex import (
    CodexAccountState,
    CodexAppServerClient,
    CodexProviderError,
    OfficialCodexAppServerClient,
)
from netsage.ai.providers.openai import (
    KeyringOpenAIAPIKeyStore,
    OfficialOpenAIServiceClient,
    OpenAIAccountState,
    OpenAIAPIKeyStore,
    OpenAIAuthStoreError,
    OpenAIErrorCode,
    OpenAIModel,
    OpenAINotAuthenticatedError,
    OpenAIProviderError,
    OpenAIServiceClient,
)
from netsage.ai.providers.selection import select_preferred_openai_provider
from netsage.credentials import CredentialStoreError, KeyringSecretStore
from netsage.drivers.fortios import FortiOSParseError, FortiOSTransportError
from netsage.history import HistoryError
from netsage.inventory import UnknownDeviceError
from netsage.state import (
    InvalidStateReferenceError,
    LocalState,
    OpenAIProviderSettings,
    OpenAIReasoningEffort,
    SSHHostIdentityChangedError,
    SSHTrustError,
    StateError,
)

OPENAI_API_KEYS_URL = "https://platform.openai.com/api-keys"
_EFFORT_ADAPTER: TypeAdapter[OpenAIReasoningEffort] = TypeAdapter(OpenAIReasoningEffort)
console = Console()
ai_app = typer.Typer(
    name="ai",
    help="Manage real AI providers without exposing provider credentials to models.",
    no_args_is_help=True,
)
openai_app = typer.Typer(
    name="openai",
    help="Configure the direct OpenAI API fallback used when Codex is absent.",
    no_args_is_help=True,
)
ai_app.add_typer(openai_app)


@dataclass(frozen=True, slots=True)
class OpenAIStatusSnapshot:
    account: OpenAIAccountState
    models: tuple[OpenAIModel, ...]
    selected_model: str
    selected_available: bool
    credential_store_available: bool = True


def _state() -> LocalState:
    state = LocalState()
    state.initialize()
    return state


def _settings(state: LocalState) -> OpenAIProviderSettings:
    return state.settings.load().ai.openai


def _api_keys() -> OpenAIAPIKeyStore:
    return KeyringOpenAIAPIKeyStore()


def _client() -> OpenAIServiceClient:
    return OfficialOpenAIServiceClient()


def _codex_client() -> CodexAppServerClient:
    return OfficialCodexAppServerClient()


def _fail(error: AIProviderError) -> typer.Exit:
    console.print(f"[red]{error.code}:[/red] {error}")
    return typer.Exit(code=1)


async def _codex_account(client: CodexAppServerClient) -> CodexAccountState:
    try:
        return await client.account_state()
    finally:
        await client.close()


async def _status_snapshot(
    settings: OpenAIProviderSettings,
    api_keys: OpenAIAPIKeyStore,
    client: OpenAIServiceClient,
) -> OpenAIStatusSnapshot:
    try:
        api_key = api_keys.get_api_key()
    except OpenAINotAuthenticatedError:
        return OpenAIStatusSnapshot(
            account=OpenAIAccountState(authenticated=False),
            models=(),
            selected_model=settings.model,
            selected_available=False,
        )
    except OpenAIAuthStoreError:
        return OpenAIStatusSnapshot(
            account=OpenAIAccountState(authenticated=False),
            models=(),
            selected_model=settings.model,
            selected_available=False,
            credential_store_available=False,
        )
    models = await client.list_models(api_key)
    return OpenAIStatusSnapshot(
        account=OpenAIAccountState(authenticated=True, auth_mode="api_key"),
        models=models,
        selected_model=settings.model,
        selected_available=settings.model in {item.id for item in models},
    )


def ai_doctor_checks() -> tuple[tuple[str, str, str], ...]:
    """Return safe automatic-runtime diagnostics without exposing auth material."""

    try:
        codex = asyncio.run(_codex_account(_codex_client()))
        state = LocalState()
        settings = (
            state.settings.load().ai.openai
            if state.paths.settings.exists()
            else OpenAIProviderSettings()
        )
        if codex.installed:
            try:
                api_fallback = _api_keys().has_api_key()
                fallback_status = "READY" if api_fallback else "NOT CONFIGURED"
            except OpenAIAuthStoreError:
                fallback_status = "UNAVAILABLE"
            return (
                (
                    "AI Runtime",
                    "OK" if codex.authenticated else "MISSING",
                    "Codex App Server (preferred)",
                ),
                (
                    "Codex Auth",
                    "OK" if codex.authenticated else "MISSING",
                    _codex_auth_details(codex),
                ),
                (
                    "OpenAI API Fallback",
                    fallback_status,
                    "used only when Codex is not installed",
                ),
            )
        snapshot = asyncio.run(_status_snapshot(settings, _api_keys(), _client()))
    except CodexProviderError:
        return (
            ("AI Runtime", "ERROR", "installed Codex App Server is unavailable"),
            ("Codex Auth", "UNKNOWN", "run: codex login status"),
            ("OpenAI API Fallback", "NOT SELECTED", "Codex is installed"),
        )
    except (StateError, OpenAIProviderError):
        return (
            ("AI Runtime", "ERROR", "direct OpenAI API unavailable"),
            ("OpenAI Auth", "UNKNOWN", "not checked"),
            ("OpenAI Model", "UNKNOWN", "not checked"),
        )
    return (
        ("AI Runtime", "OK", "OpenAI API (Codex not installed)"),
        (
            "OpenAI Auth",
            (
                "OK"
                if snapshot.account.authenticated
                else "MISSING"
                if snapshot.credential_store_available
                else "UNAVAILABLE"
            ),
            "API key in OS credential store"
            if snapshot.account.authenticated
            else "run: netsage ai openai login"
            if snapshot.credential_store_available
            else "secure OS credential store unavailable",
        ),
        (
            "OpenAI Model",
            "OK" if snapshot.selected_available else "UNVERIFIED",
            snapshot.selected_model,
        ),
    )


# Compatibility name for callers from the direct-API milestone.
openai_doctor_checks = ai_doctor_checks


def _codex_auth_details(account: CodexAccountState) -> str:
    if not account.authenticated:
        return "run: codex login"
    if account.auth_mode == "chatgpt" and account.plan_type is not None:
        return f"ChatGPT managed ({account.plan_type})"
    return f"Codex managed ({account.auth_mode})"


@ai_app.command("status")
def ai_status() -> None:
    """Show the automatic Codex-first runtime selection and fallback readiness."""

    try:
        codex = asyncio.run(_codex_account(_codex_client()))
        api_keys = _api_keys()
        try:
            api_ready = api_keys.has_api_key()
            api_status = "READY" if api_ready else "NOT CONFIGURED"
        except OpenAIAuthStoreError:
            api_status = "UNAVAILABLE"
    except CodexProviderError as error:
        raise _fail(error) from error
    table = Table(title="NetSage AI runtime selection")
    table.add_column("Area")
    table.add_column("Status")
    table.add_column("Details")
    table.add_row(
        "Selected runtime",
        "OK" if (not codex.installed or codex.authenticated) else "NOT AUTHENTICATED",
        "Codex App Server" if codex.installed else "OpenAI API",
    )
    table.add_row(
        "Codex",
        "OK" if codex.authenticated else "NOT AUTHENTICATED" if codex.installed else "ABSENT",
        _codex_auth_details(codex) if codex.installed else "not found on PATH",
    )
    table.add_row(
        "OpenAI API fallback",
        api_status,
        "selected only when Codex is absent",
    )
    console.print(table)


@openai_app.command("status")
def openai_status() -> None:
    """Show direct OpenAI API fallback authentication and model status."""

    try:
        state = _state()
        snapshot = asyncio.run(_status_snapshot(_settings(state), _api_keys(), _client()))
    except StateError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    except OpenAIProviderError as error:
        raise _fail(error) from error
    table = Table(title="NetSage OpenAI status")
    table.add_column("Area")
    table.add_column("Status")
    table.add_column("Details")
    table.add_row("Provider", "OK", "OpenAI Responses API")
    table.add_row(
        "Authentication",
        (
            "OK"
            if snapshot.account.authenticated
            else "NOT AUTHENTICATED"
            if snapshot.credential_store_available
            else "UNAVAILABLE"
        ),
        "API key in OS credential store"
        if snapshot.account.authenticated
        else "Run: netsage ai openai login"
        if snapshot.credential_store_available
        else "Secure OS credential store unavailable",
    )
    table.add_row(
        "Model",
        "OK" if snapshot.selected_available else "UNVERIFIED",
        snapshot.selected_model,
    )
    console.print(table)


@openai_app.command("login")
def openai_login(
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not open the official OpenAI API-key page.",
    ),
) -> None:
    """Validate an API key and store it in the separate provider OS keyring."""

    console.print("OpenAI Provider Setup")
    console.print("This configures the direct API fallback used when Codex is absent.")
    console.print("Authentication uses an OpenAI API key stored separately by NetSage.")
    if not no_browser:
        console.print("Opening the official OpenAI API-key page.")
        webbrowser.open(OPENAI_API_KEYS_URL)
    api_key_value = typer.prompt("OpenAI API key", hide_input=True)
    api_key = SecretStr(api_key_value)
    try:
        models = asyncio.run(_client().list_models(api_key))
        if not models:
            raise OpenAIProviderError(
                OpenAIErrorCode.AUTHENTICATION_FAILED,
                "OpenAI authentication returned no available models.",
            )
        _api_keys().set_api_key(api_key)
    except OpenAIAuthStoreError as error:
        console.print("[red]OpenAI API key could not be stored securely.[/red]")
        raise typer.Exit(code=1) from error
    except OpenAIProviderError as error:
        raise _fail(error) from error
    finally:
        api_key_value = ""
        api_key = SecretStr("")
    console.print("OpenAI authentication verified.")
    console.print("API key storage: separate OS credential-store entry; never AI context or YAML.")


@openai_app.command("logout")
def openai_logout() -> None:
    """Remove only the OpenAI provider API key from OS credential storage."""

    try:
        _api_keys().delete_api_key(missing_ok=True)
    except OpenAIAuthStoreError as error:
        console.print("[red]OpenAI authentication could not be removed.[/red]")
        raise typer.Exit(code=1) from error
    console.print("OpenAI provider authentication removed.")


@openai_app.command("models")
def openai_models() -> None:
    """List models available to the authenticated OpenAI API project."""

    try:
        state = _state()
        snapshot = asyncio.run(_status_snapshot(_settings(state), _api_keys(), _client()))
    except StateError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    except OpenAIProviderError as error:
        raise _fail(error) from error
    if not snapshot.account.authenticated:
        raise _fail(
            OpenAIProviderError(
                OpenAIErrorCode.NOT_AUTHENTICATED,
                "OpenAI is not authenticated. Run: netsage ai openai login",
            )
        )
    table = Table(title="OpenAI models")
    table.add_column("Model")
    table.add_column("Selected")
    table.add_column("Owner")
    table.add_column("Shutdown")
    for model in snapshot.models:
        table.add_row(
            model.id,
            "yes" if model.id == snapshot.selected_model else "",
            model.owned_by,
            model.shutdown_date or "-",
        )
    console.print(table)


@openai_app.command("configure")
def openai_configure(
    model: str | None = typer.Option(None, "--model", help="Preferred API model ID."),
    reasoning_effort: str | None = typer.Option(
        None,
        "--effort",
        help="Reasoning effort: none|minimal|low|medium|high|xhigh|max.",
    ),
    defaults: bool = typer.Option(False, "--defaults", help="Restore NetSage defaults."),
) -> None:
    """Persist only non-sensitive OpenAI model preferences."""

    if defaults and (model is not None or reasoning_effort is not None):
        console.print("[red]Use --defaults alone.[/red]")
        raise typer.Exit(code=1)
    try:
        state = _state()
        document = state.settings.load()
        current = document.ai.openai
        updated = (
            OpenAIProviderSettings()
            if defaults
            else OpenAIProviderSettings(
                model=model if model is not None else current.model,
                reasoning_effort=(
                    _EFFORT_ADAPTER.validate_python(reasoning_effort)
                    if reasoning_effort is not None
                    else current.reasoning_effort
                ),
            )
        )
        state.settings.save(
            document.model_copy(update={"ai": document.ai.model_copy(update={"openai": updated})})
        )
    except (StateError, ValueError) as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    console.print("OpenAI provider preferences saved. No API key was written to YAML.")


def ask_device(device_id: str, question: str) -> None:
    """Use installed Codex when present; otherwise use the direct OpenAI API."""

    try:
        state = _state()
        selection = select_preferred_openai_provider(
            _settings(state),
            codex_client=_codex_client(),
            api_keys=_api_keys(),
            openai_client=_client(),
        )
        report = asyncio.run(
            FortiOSAIInvestigationService(
                state=state,
                secrets=KeyringSecretStore(),
                provider=selection.provider,
                provider_name=selection.provider_id,
            ).ask(device_id, question)
        )
    except AIProviderError as error:
        raise _fail(error) from error
    except (
        UnknownDeviceError,
        InvalidStateReferenceError,
        CredentialStoreError,
        FortiOSParseError,
        FortiOSTransportError,
        SSHHostIdentityChangedError,
        SSHTrustError,
        HistoryError,
        StateError,
        ValueError,
    ) as error:
        console.print(f"[red]AI investigation failed:[/red] {error}")
        raise typer.Exit(code=1) from error
    console.print(render_agent_report(report))
    if report.state is not AgentRuntimeState.COMPLETED:
        raise typer.Exit(code=1)
