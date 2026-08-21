"""Deterministic local-runtime selection for OpenAI-backed reasoning."""

from dataclasses import dataclass
from typing import Literal

from netsage.ai import AIProvider
from netsage.ai.providers.codex import CodexAppServerClient, CodexProvider
from netsage.ai.providers.openai import (
    OpenAIAPIKeyStore,
    OpenAIProvider,
    OpenAIServiceClient,
)
from netsage.state import OpenAIProviderSettings


@dataclass(frozen=True, slots=True)
class SelectedAIProvider:
    provider: AIProvider
    provider_id: Literal["codex", "openai"]
    display_name: str


def select_preferred_openai_provider(
    settings: OpenAIProviderSettings,
    *,
    codex_client: CodexAppServerClient,
    api_keys: OpenAIAPIKeyStore,
    openai_client: OpenAIServiceClient,
) -> SelectedAIProvider:
    """Prefer installed Codex; use direct API only when Codex is absent."""

    if codex_client.installed:
        return SelectedAIProvider(
            provider=CodexProvider(settings, client=codex_client),
            provider_id="codex",
            display_name="Codex App Server",
        )
    return SelectedAIProvider(
        provider=OpenAIProvider(settings, api_keys=api_keys, client=openai_client),
        provider_id="openai",
        display_name="OpenAI API",
    )
