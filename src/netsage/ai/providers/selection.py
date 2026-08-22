"""Visible, deterministic selection of separate OpenAI-backed auth domains."""

from dataclasses import dataclass
from typing import Literal

from netsage.ai import AIProvider, AIProviderError
from netsage.ai.providers.codex import CodexAppServerClient, CodexProvider
from netsage.ai.providers.openai import (
    OpenAIAPIKeyStore,
    OpenAIAuthStoreError,
    OpenAIProvider,
    OpenAIServiceClient,
)
from netsage.ai.providers.openai_codex import (
    CodexOAuthCredentialStoreError,
    CodexOAuthProvider,
)
from netsage.state import AIProviderChoice, OpenAIProviderSettings


class AIProviderSelectionError(AIProviderError):
    pass


@dataclass(frozen=True, slots=True)
class SelectedAIProvider:
    provider: AIProvider
    provider_id: Literal["openai-codex", "codex-app-server", "openai-api"]
    display_name: str


def select_preferred_openai_provider(
    settings: OpenAIProviderSettings,
    *,
    provider_choice: AIProviderChoice = "auto",
    codex_oauth_provider: CodexOAuthProvider,
    codex_client: CodexAppServerClient,
    api_keys: OpenAIAPIKeyStore,
    openai_client: OpenAIServiceClient,
) -> SelectedAIProvider:
    """Keep subscription OAuth, optional App Server, and API billing distinct."""

    if provider_choice == "openai-codex":
        return SelectedAIProvider(
            provider=codex_oauth_provider,
            provider_id="openai-codex",
            display_name="OpenAI Codex OAuth",
        )
    if provider_choice == "codex-app-server":
        return SelectedAIProvider(
            provider=CodexProvider(settings, client=codex_client),
            provider_id="codex-app-server",
            display_name="Codex App Server",
        )
    if provider_choice == "openai-api":
        return SelectedAIProvider(
            provider=OpenAIProvider(settings, api_keys=api_keys, client=openai_client),
            provider_id="openai-api",
            display_name="OpenAI API",
        )

    try:
        oauth_configured = codex_oauth_provider.configured
    except CodexOAuthCredentialStoreError as error:
        raise AIProviderSelectionError(
            "Codex OAuth credential storage is unavailable.",
            code="AI_CREDENTIAL_STORE_UNAVAILABLE",
        ) from error
    if oauth_configured:
        return SelectedAIProvider(
            provider=codex_oauth_provider,
            provider_id="openai-codex",
            display_name="OpenAI Codex OAuth",
        )

    if codex_client.installed:
        return SelectedAIProvider(
            provider=CodexProvider(settings, client=codex_client),
            provider_id="codex-app-server",
            display_name="Codex App Server",
        )
    try:
        api_configured = api_keys.has_api_key()
    except OpenAIAuthStoreError as error:
        raise AIProviderSelectionError(
            "OpenAI API credential storage is unavailable.",
            code="AI_CREDENTIAL_STORE_UNAVAILABLE",
        ) from error
    if api_configured:
        return SelectedAIProvider(
            provider=OpenAIProvider(settings, api_keys=api_keys, client=openai_client),
            provider_id="openai-api",
            display_name="OpenAI API",
        )
    raise AIProviderSelectionError(
        "No AI provider is configured. Run: netsage ai codex login",
        code="AI_PROVIDER_NOT_CONFIGURED",
    )
