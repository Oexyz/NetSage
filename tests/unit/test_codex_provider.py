from collections import deque
from datetime import UTC, datetime
from uuid import UUID

import pytest

from netsage.ai import AIContext, AIDeviceContext
from netsage.ai.providers.codex import (
    CodexAccountState,
    CodexAppServerClient,
    CodexErrorCode,
    CodexProvider,
    CodexProviderError,
    CodexStructuredOutput,
)
from netsage.ai.providers.openai import (
    InMemoryOpenAIAPIKeyStore,
    OpenAIModel,
    OpenAIServiceClient,
    OpenAIStructuredOutput,
)
from netsage.ai.providers.openai_codex import (
    CodexOAuthProvider,
    CodexOAuthTokenBundle,
    CodexOAuthTokenManager,
    InMemoryCodexOAuthTokenStore,
)
from netsage.ai.providers.selection import select_preferred_openai_provider
from netsage.models import Capability, Platform
from netsage.state import OpenAIProviderSettings


class FakeCodexClient(CodexAppServerClient):
    def __init__(
        self,
        *,
        installed: bool = True,
        authenticated: bool = True,
        responses: tuple[CodexStructuredOutput, ...] = (),
    ) -> None:
        self._installed = installed
        self.authenticated = authenticated
        self.responses = deque(responses)
        self.inputs: list[str] = []
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

    async def complete_structured(
        self,
        *,
        input_text: str,
        instructions: str,
        reasoning_effort: str,
    ) -> CodexStructuredOutput:
        assert "Do not execute commands" in instructions
        assert reasoning_effort == "medium"
        self.inputs.append(input_text)
        if not self.responses:
            raise AssertionError("No scripted Codex response")
        return self.responses.popleft()

    async def close(self) -> None:
        self.closed = True


class NeverUsedOpenAIClient(OpenAIServiceClient):
    async def list_models(self, _api_key: object) -> tuple[OpenAIModel, ...]:
        raise AssertionError("Codex selection must not access the OpenAI API")


class NeverRefreshCodexOAuth:
    async def refresh_tokens(self, _tokens: CodexOAuthTokenBundle) -> CodexOAuthTokenBundle:
        raise AssertionError("unconfigured native OAuth must not refresh")


def unconfigured_native_oauth() -> CodexOAuthProvider:
    return CodexOAuthProvider(
        OpenAIProviderSettings(),
        tokens=CodexOAuthTokenManager(
            store=InMemoryCodexOAuthTokenStore(),
            refresh_client=NeverRefreshCodexOAuth(),
        ),
    )

    async def complete_structured(
        self, *_args: object, **_kwargs: object
    ) -> OpenAIStructuredOutput:
        raise AssertionError("Codex selection must not access the OpenAI API")


def context() -> AIContext:
    return AIContext(
        investigation_id=UUID(int=501),
        user_request="Assess the available evidence.",
        device=AIDeviceContext(
            device_id="fortigate-example",
            platform=Platform.FORTIOS,
            capabilities=(Capability.ROUTES,),
        ),
        evidence=(),
        deterministic_findings=(),
        missing_evidence=(),
    )


def final_output() -> CodexStructuredOutput:
    return CodexStructuredOutput(
        response_type="final",
        summary="Evidence is insufficient.",
        diagnosis_strength="insufficient",
        evidence_ids=(),
        limitations=("No observations supplied.",),
        tool_calls=(),
    )


@pytest.mark.asyncio
async def test_codex_provider_returns_typed_response_and_closes_client() -> None:
    client = FakeCodexClient(responses=(final_output(),))
    provider = CodexProvider(OpenAIProviderSettings(), client=client)

    response = await provider.generate(context(), tools=(), tool_results=())
    await provider.close()

    assert response.response_type == "final"
    assert client.inputs
    assert "untrusted data" in client.inputs[0]
    assert client.closed is True


@pytest.mark.asyncio
async def test_installed_codex_requires_its_own_managed_login() -> None:
    provider = CodexProvider(
        OpenAIProviderSettings(),
        client=FakeCodexClient(authenticated=False),
    )

    with pytest.raises(CodexProviderError) as caught:
        await provider.initialize()

    assert caught.value.code == CodexErrorCode.NOT_AUTHENTICATED.value
    assert "codex login" in str(caught.value)


@pytest.mark.asyncio
async def test_codex_semantically_invalid_final_response_is_bounded() -> None:
    invalid = CodexStructuredOutput(
        response_type="final",
        summary="Unsupported strong diagnosis.",
        diagnosis_strength="strong",
        evidence_ids=(),
        limitations=(),
        tool_calls=(),
    )
    provider = CodexProvider(
        OpenAIProviderSettings(),
        client=FakeCodexClient(responses=(invalid,)),
    )

    with pytest.raises(CodexProviderError) as caught:
        await provider.generate(context(), tools=(), tool_results=())

    assert caught.value.code == CodexErrorCode.OUTPUT_INVALID.value


def test_provider_selection_prefers_installed_codex_without_resolving_api_key() -> None:
    codex = FakeCodexClient()
    selection = select_preferred_openai_provider(
        OpenAIProviderSettings(),
        codex_oauth_provider=unconfigured_native_oauth(),
        codex_client=codex,
        api_keys=InMemoryOpenAIAPIKeyStore(),
        openai_client=NeverUsedOpenAIClient(),
    )

    assert selection.provider_id == "codex-app-server"
    assert isinstance(selection.provider, CodexProvider)


def test_provider_selection_uses_direct_api_only_when_codex_is_absent() -> None:
    selection = select_preferred_openai_provider(
        OpenAIProviderSettings(),
        codex_oauth_provider=unconfigured_native_oauth(),
        codex_client=FakeCodexClient(installed=False, authenticated=False),
        api_keys=InMemoryOpenAIAPIKeyStore("sk-synthetic-fallback"),
        openai_client=NeverUsedOpenAIClient(),
    )

    assert selection.provider_id == "openai-api"


def test_codex_account_state_discards_time_and_identity_context() -> None:
    state = CodexAccountState(
        installed=True,
        authenticated=True,
        auth_mode="chatgpt",
        plan_type="plus",
    )

    assert datetime.now(UTC).isoformat() not in state.model_dump_json()
    assert set(state.model_dump()) == {"installed", "authenticated", "auth_mode", "plan_type"}
