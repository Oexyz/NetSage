"""Official OpenAI Python SDK boundary for models and Structured Outputs."""

from __future__ import annotations

from typing import Protocol

from openai import (
    APIConnectionError,
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    AuthenticationError,
    OpenAIError,
)
from pydantic import SecretStr

from netsage.ai.base import AIProviderError
from netsage.ai.providers.openai.models import (
    OpenAIErrorCode,
    OpenAIModel,
    OpenAIStructuredOutput,
)
from netsage.state import OpenAIReasoningEffort


class OpenAIProviderError(AIProviderError):
    def __init__(self, code: OpenAIErrorCode, message: str) -> None:
        super().__init__(message, code=code.value)
        self.openai_code = code


class OpenAIServiceClient(Protocol):
    async def list_models(self, api_key: SecretStr) -> tuple[OpenAIModel, ...]: ...

    async def complete_structured(
        self,
        api_key: SecretStr,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: OpenAIReasoningEffort,
    ) -> OpenAIStructuredOutput: ...


class OfficialOpenAIServiceClient(OpenAIServiceClient):
    """Expose no OpenAI built-in tools and request no provider-side persistence."""

    def __init__(self, *, timeout: float = 300.0, max_retries: int = 2) -> None:
        self._timeout = timeout
        self._max_retries = max_retries

    async def list_models(self, api_key: SecretStr) -> tuple[OpenAIModel, ...]:
        client = self._client(api_key)
        try:
            page = await client.models.list()
            return tuple(
                sorted(
                    (
                        OpenAIModel(
                            id=item.id,
                            owned_by=item.owned_by,
                        )
                        for item in page.data
                    ),
                    key=lambda item: item.id,
                )
            )
        except Exception as error:
            raise _safe_openai_error(error) from error
        finally:
            await client.close()

    async def complete_structured(
        self,
        api_key: SecretStr,
        *,
        input_text: str,
        instructions: str,
        model: str,
        reasoning_effort: OpenAIReasoningEffort,
    ) -> OpenAIStructuredOutput:
        client = self._client(api_key)
        try:
            response = await client.responses.parse(
                model=model,
                instructions=instructions,
                input=input_text,
                reasoning={"effort": reasoning_effort},
                text_format=OpenAIStructuredOutput,
                tools=[],
                parallel_tool_calls=False,
                store=False,
            )
            parsed = response.output_parsed
            if parsed is None:
                raise OpenAIProviderError(
                    OpenAIErrorCode.OUTPUT_INVALID,
                    "OpenAI returned no validated structured provider response.",
                )
            return parsed
        except OpenAIProviderError:
            raise
        except Exception as error:
            raise _safe_openai_error(error) from error
        finally:
            await client.close()

    def _client(self, api_key: SecretStr) -> AsyncOpenAI:
        return AsyncOpenAI(
            api_key=api_key.get_secret_value(),
            timeout=self._timeout,
            max_retries=self._max_retries,
        )


def _safe_openai_error(error: Exception) -> OpenAIProviderError:
    if isinstance(error, AuthenticationError):
        return OpenAIProviderError(
            OpenAIErrorCode.AUTHENTICATION_FAILED,
            "OpenAI API-key authentication failed.",
        )
    if isinstance(error, APITimeoutError):
        return OpenAIProviderError(OpenAIErrorCode.TIMEOUT, "OpenAI request timed out.")
    if isinstance(error, APIStatusError) and error.status_code == 404:
        return OpenAIProviderError(
            OpenAIErrorCode.MODEL_UNAVAILABLE,
            "The configured OpenAI model is unavailable.",
        )
    if isinstance(error, APIConnectionError | APIStatusError | OpenAIError):
        return OpenAIProviderError(OpenAIErrorCode.API_ERROR, "OpenAI API request failed.")
    return OpenAIProviderError(OpenAIErrorCode.API_ERROR, "OpenAI provider failed.")
