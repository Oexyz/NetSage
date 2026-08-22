"""Separated native OAuth, optional App Server, OpenAI API, and ask CLI."""

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
from netsage.ai.providers.openai_codex import (
    CodexExistingAuthImporter,
    CodexExistingAuthImportError,
    CodexOAuthCredentialStoreError,
    CodexOAuthHTTPClient,
    CodexOAuthInferenceClient,
    CodexOAuthProtocolError,
    CodexOAuthProvider,
    CodexOAuthStatus,
    CodexOAuthTokenManager,
    CodexOAuthTokenStore,
    KeyringCodexOAuthTokenStore,
    OfficialCodexOAuthInferenceClient,
)
from netsage.ai.providers.openai_codex.protocol import EXPERIMENTAL_COMPATIBILITY_NOTICE
from netsage.ai.providers.selection import select_preferred_openai_provider
from netsage.credentials import CredentialStoreError, KeyringSecretStore
from netsage.drivers.fortios import FortiOSParseError, FortiOSTransportError
from netsage.history import HistoryError
from netsage.inventory import UnknownDeviceError
from netsage.state import (
    AIProviderChoice,
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
_PROVIDER_ADAPTER: TypeAdapter[AIProviderChoice] = TypeAdapter(AIProviderChoice)
console = Console()
ai_app = typer.Typer(
    name="ai",
    help="Manage real AI providers without exposing provider credentials to models.",
    no_args_is_help=True,
)
openai_app = typer.Typer(
    name="openai",
    help="Configure the separate usage-based OpenAI API provider.",
    no_args_is_help=True,
)
codex_oauth_app = typer.Typer(
    name="codex",
    help="Manage experimental native ChatGPT/Codex OAuth without requiring Codex CLI.",
    no_args_is_help=True,
)
ai_app.add_typer(openai_app)
ai_app.add_typer(codex_oauth_app)


@dataclass(frozen=True, slots=True)
class OpenAIStatusSnapshot:
    account: OpenAIAccountState
    models: tuple[OpenAIModel, ...]
    selected_model: str
    selected_available: bool
    credential_store_available: bool = True


@dataclass(frozen=True, slots=True)
class AIRuntimeStatusSnapshot:
    provider_choice: AIProviderChoice
    oauth: CodexOAuthStatus | None
    oauth_store_available: bool
    app_server: CodexAccountState
    app_server_available: bool
    api_configured: bool
    api_store_available: bool


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


def _codex_oauth_store() -> CodexOAuthTokenStore:
    return KeyringCodexOAuthTokenStore()


def _codex_oauth_http_client() -> CodexOAuthHTTPClient:
    return CodexOAuthHTTPClient()


def _codex_oauth_inference_client() -> CodexOAuthInferenceClient:
    return OfficialCodexOAuthInferenceClient()


def _codex_oauth_manager(
    store: CodexOAuthTokenStore | None = None,
    client: CodexOAuthHTTPClient | None = None,
) -> CodexOAuthTokenManager:
    resolved_store = store or _codex_oauth_store()
    resolved_client = client or _codex_oauth_http_client()
    return CodexOAuthTokenManager(store=resolved_store, refresh_client=resolved_client)


def _codex_oauth_provider(
    settings: OpenAIProviderSettings,
    *,
    store: CodexOAuthTokenStore | None = None,
    protocol: CodexOAuthHTTPClient | None = None,
    inference: CodexOAuthInferenceClient | None = None,
) -> CodexOAuthProvider:
    return CodexOAuthProvider(
        settings,
        tokens=_codex_oauth_manager(store, protocol),
        client=inference or _codex_oauth_inference_client(),
    )


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


def _runtime_status_snapshot() -> AIRuntimeStatusSnapshot:
    state = LocalState()
    choice: AIProviderChoice = (
        state.settings.load().ai.provider if state.paths.settings.exists() else "auto"
    )
    try:
        oauth = _codex_oauth_manager().status()
        oauth_store_available = True
    except CodexOAuthCredentialStoreError:
        oauth = None
        oauth_store_available = False
    try:
        app_server = asyncio.run(_codex_account(_codex_client()))
        app_server_available = True
    except CodexProviderError:
        app_server = CodexAccountState(installed=True, authenticated=False)
        app_server_available = False
    try:
        api_configured = _api_keys().has_api_key()
        api_store_available = True
    except OpenAIAuthStoreError:
        api_configured = False
        api_store_available = False
    return AIRuntimeStatusSnapshot(
        provider_choice=choice,
        oauth=oauth,
        oauth_store_available=oauth_store_available,
        app_server=app_server,
        app_server_available=app_server_available,
        api_configured=api_configured,
        api_store_available=api_store_available,
    )


def _effective_provider(snapshot: AIRuntimeStatusSnapshot) -> str | None:
    choice = "auto" if snapshot.provider_choice == "openai" else snapshot.provider_choice
    if choice != "auto":
        return choice
    if snapshot.oauth is not None and snapshot.oauth.configured:
        return "openai-codex"
    if snapshot.app_server.installed:
        return "codex-app-server"
    if snapshot.api_configured:
        return "openai-api"
    return None


def _provider_ready(snapshot: AIRuntimeStatusSnapshot, provider_id: str | None) -> bool:
    if provider_id == "openai-codex":
        return snapshot.oauth is not None and snapshot.oauth.authenticated
    if provider_id == "codex-app-server":
        return snapshot.app_server_available and snapshot.app_server.authenticated
    if provider_id == "openai-api":
        return snapshot.api_store_available and snapshot.api_configured
    return False


def _provider_display(provider_id: str | None) -> str:
    if provider_id is None:
        return "No AI provider"
    return {
        "openai-codex": "OpenAI Codex",
        "codex-app-server": "Codex App Server",
        "openai-api": "OpenAI API",
    }.get(provider_id, "Unknown AI provider")


def ai_doctor_checks() -> tuple[tuple[str, str, str], ...]:
    """Return safe automatic-runtime diagnostics without exposing auth material."""

    try:
        snapshot = _runtime_status_snapshot()
    except StateError:
        return (
            ("AI Runtime", "ERROR", "provider state unavailable"),
            ("Codex OAuth", "UNKNOWN", "not checked"),
            ("OpenAI API", "UNKNOWN", "not checked"),
        )
    selected = _effective_provider(snapshot)
    return (
        (
            "AI Runtime",
            "OK" if _provider_ready(snapshot, selected) else "MISSING",
            _provider_display(selected),
        ),
        (
            "Codex OAuth",
            (
                "OK"
                if snapshot.oauth is not None and snapshot.oauth.authenticated
                else "MISSING"
                if snapshot.oauth_store_available
                else "UNAVAILABLE"
            ),
            "ChatGPT subscription; native experimental compatibility",
        ),
        (
            "OpenAI API",
            "OK"
            if snapshot.api_configured
            else "MISSING"
            if snapshot.api_store_available
            else "UNAVAILABLE",
            "usage-based API; separate credential domain",
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
    """Show explicit provider/auth/billing routes without revealing credentials."""

    try:
        snapshot = _runtime_status_snapshot()
    except StateError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    selected = _effective_provider(snapshot)
    table = Table(title="NetSage AI runtime selection")
    table.add_column("Area")
    table.add_column("Status")
    table.add_column("Details")
    table.add_row(
        "Selected provider",
        "OK" if _provider_ready(snapshot, selected) else "NOT AUTHENTICATED",
        _provider_display(selected),
    )
    table.add_row(
        "Selection mode",
        "OK",
        "auto" if snapshot.provider_choice == "openai" else snapshot.provider_choice,
    )
    oauth = snapshot.oauth
    table.add_row(
        "OpenAI Codex OAuth",
        (
            "OK"
            if oauth is not None and oauth.authenticated
            else "NOT AUTHENTICATED"
            if snapshot.oauth_store_available
            else "UNAVAILABLE"
        ),
        (
            f"ChatGPT OAuth; ChatGPT subscription; {oauth.token_state.value}; experimental"
            if oauth is not None and oauth.configured
            else "Run: netsage ai codex login; experimental compatibility"
            if snapshot.oauth_store_available
            else "Secure OS credential store unavailable"
        ),
    )
    table.add_row(
        "Existing Codex App Server",
        (
            "OK"
            if snapshot.app_server.authenticated
            else "NOT AUTHENTICATED"
            if snapshot.app_server.installed
            else "ABSENT"
        ),
        (
            _codex_auth_details(snapshot.app_server)
            if snapshot.app_server.installed
            else "optional; Codex CLI is not required"
        ),
    )
    table.add_row(
        "OpenAI API",
        "READY"
        if snapshot.api_configured
        else "NOT CONFIGURED"
        if snapshot.api_store_available
        else "UNAVAILABLE",
        "API key; usage-based API; never receives Codex OAuth tokens",
    )
    console.print(table)


def _set_provider_choice(state: LocalState, choice: AIProviderChoice) -> None:
    document = state.settings.load()
    state.settings.save(
        document.model_copy(update={"ai": document.ai.model_copy(update={"provider": choice})})
    )


@ai_app.command("configure")
def ai_configure(
    provider: str = typer.Option(
        ...,
        "--provider",
        help="auto|openai-codex|codex-app-server|openai-api",
    ),
) -> None:
    """Select an explicit provider route or the visible auto-priority policy."""

    if provider == "openai":
        provider = "auto"
    try:
        choice = _PROVIDER_ADAPTER.validate_python(provider)
        state = _state()
        _set_provider_choice(state, choice)
    except (StateError, ValueError) as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    console.print(f"AI provider selection saved: {choice}")
    console.print("No provider credential was written to YAML.")


@codex_oauth_app.command("status")
def codex_oauth_status() -> None:
    """Show only secret-free native OAuth configuration and expiry state."""

    try:
        status = _codex_oauth_manager().status()
    except CodexOAuthCredentialStoreError as error:
        console.print("[red]Codex OAuth credential storage is unavailable.[/red]")
        raise typer.Exit(code=1) from error
    table = Table(title="NetSage OpenAI Codex OAuth status")
    table.add_column("Area")
    table.add_column("Status")
    table.add_column("Details")
    table.add_row("Provider", "EXPERIMENTAL", "ChatGPT/Codex OAuth compatibility")
    table.add_row(
        "Configured",
        "YES" if status.configured else "NO",
        "OS credential store" if status.configured else "Run: netsage ai codex login",
    )
    table.add_row(
        "Authenticated",
        "YES" if status.authenticated else "NO",
        "ChatGPT OAuth" if status.configured else "not configured",
    )
    table.add_row("Token", status.token_state.value.upper(), "Token values are never displayed")
    console.print(table)


@codex_oauth_app.command("login")
def codex_oauth_login(
    no_browser: bool = typer.Option(
        False,
        "--no-browser",
        help="Do not open the device-authorization page automatically.",
    ),
) -> None:
    """Authenticate natively with ChatGPT; no Codex executable or API key required."""

    console.print("ChatGPT / Codex authentication")
    console.print(EXPERIMENTAL_COMPATIBILITY_NOTICE)
    protocol = _codex_oauth_http_client()
    store = _codex_oauth_store()
    try:
        authorization = asyncio.run(protocol.request_device_authorization())
        user_code = authorization.user_code.get_secret_value()
        console.print("Open:")
        console.print(authorization.verification_url, markup=False)
        console.print("Code:")
        console.print(user_code, markup=False)
        if not no_browser:
            webbrowser.open(authorization.verification_url)
        console.print("Waiting for authentication... Press Ctrl+C to cancel.")
        tokens = asyncio.run(protocol.complete_device_authorization(authorization))
        store.save(tokens)
        state = _state()
        _set_provider_choice(state, "openai-codex")
    except KeyboardInterrupt as error:
        console.print("Authentication cancelled. No credentials were stored.")
        raise typer.Exit(code=130) from error
    except CodexOAuthProtocolError as error:
        console.print(f"[red]{error.code.value}:[/red] {error}")
        raise typer.Exit(code=1) from error
    except CodexOAuthCredentialStoreError as error:
        console.print("[red]Codex OAuth credentials could not be stored securely.[/red]")
        raise typer.Exit(code=1) from error
    except StateError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    console.print("Authentication successful.")
    console.print("Access and refresh tokens: OS credential store only.")


@codex_oauth_app.command("logout")
def codex_oauth_logout() -> None:
    """Remove only NetSage-owned Codex OAuth credentials from its keyring domain."""

    try:
        _codex_oauth_store().delete(missing_ok=True)
    except CodexOAuthCredentialStoreError as error:
        console.print("[red]Codex OAuth credentials could not be removed.[/red]")
        raise typer.Exit(code=1) from error
    console.print("NetSage Codex OAuth authentication removed.")
    console.print("Existing Codex CLI and browser sessions were not changed.")


@codex_oauth_app.command("import-existing")
def codex_oauth_import_existing() -> None:
    """Explicitly copy compatible Codex auth.json tokens into NetSage keyring storage."""

    store = _codex_oauth_store()
    importer = CodexExistingAuthImporter(store)
    if not importer.detected():
        console.print("No compatible Codex auth file was detected.")
        raise typer.Exit(code=1)
    console.print("Existing Codex authentication detected.")
    console.print("A separate native NetSage login is recommended to avoid refresh-token races.")
    if not typer.confirm("Import into the NetSage OS credential store?", default=False):
        console.print("Import cancelled. The source was not read or modified.")
        return
    try:
        importer.import_file()
        state = _state()
        _set_provider_choice(state, "openai-codex")
    except (CodexExistingAuthImportError, CodexOAuthCredentialStoreError) as error:
        console.print("[red]Compatible Codex authentication could not be imported.[/red]")
        raise typer.Exit(code=1) from error
    except StateError as error:
        console.print(f"[red]{error}[/red]")
        raise typer.Exit(code=1) from error
    console.print("Existing authentication imported into the NetSage OS credential store.")
    console.print("The Codex source file was not modified.")


@openai_app.command("status")
def openai_status() -> None:
    """Show separate OpenAI API authentication and model status."""

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
    console.print("This configures the separate usage-based OpenAI API provider.")
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
    """Use the configured/visible auth route behind the same AgentRuntime."""

    try:
        state = _state()
        document = state.settings.load()
        settings = document.ai.openai
        selection = select_preferred_openai_provider(
            settings,
            provider_choice=document.ai.provider,
            codex_oauth_provider=_codex_oauth_provider(settings),
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
