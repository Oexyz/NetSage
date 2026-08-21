"""Typed, secret-free models for the direct OpenAI API provider."""

from enum import StrEnum
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, model_validator

from netsage.ai.models import AIProviderResponse


class OpenAIErrorCode(StrEnum):
    NOT_AUTHENTICATED = "OPENAI_NOT_AUTHENTICATED"
    AUTHENTICATION_FAILED = "OPENAI_AUTHENTICATION_FAILED"
    API_ERROR = "OPENAI_API_ERROR"
    TIMEOUT = "OPENAI_TIMEOUT"
    OUTPUT_INVALID = "OPENAI_OUTPUT_INVALID"
    MODEL_UNAVAILABLE = "OPENAI_MODEL_UNAVAILABLE"
    CREDENTIAL_STORE_ERROR = "OPENAI_CREDENTIAL_STORE_ERROR"


class OpenAIAccountState(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    authenticated: bool
    auth_mode: Literal["api_key"] | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.authenticated != (self.auth_mode is not None):
            raise ValueError("OpenAI account authentication state is inconsistent")
        return self


class OpenAIModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    owned_by: str
    shutdown_date: str | None = None


class OpenAIStructuredOutput(BaseModel):
    """Object-root envelope for one provider-neutral semantic response."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    response: AIProviderResponse
