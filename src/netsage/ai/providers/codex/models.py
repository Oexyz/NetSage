"""Typed, secret-free state and failures for the Codex App Server adapter."""

from enum import StrEnum
from typing import Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

from netsage.ai.models import AIProviderResponse
from netsage.investigations import DiagnosisStrength

_PROVIDER_RESPONSE_ADAPTER: TypeAdapter[AIProviderResponse] = TypeAdapter(AIProviderResponse)


class CodexErrorCode(StrEnum):
    NOT_INSTALLED = "CODEX_NOT_INSTALLED"
    NOT_AUTHENTICATED = "CODEX_NOT_AUTHENTICATED"
    APP_SERVER_UNAVAILABLE = "CODEX_APP_SERVER_UNAVAILABLE"
    PROTOCOL_ERROR = "CODEX_PROTOCOL_ERROR"
    TIMEOUT = "CODEX_TIMEOUT"
    OUTPUT_INVALID = "CODEX_OUTPUT_INVALID"
    UNSAFE_TOOL_ATTEMPT = "CODEX_UNSAFE_TOOL_ATTEMPT"


class CodexAccountState(BaseModel):
    """Minimal account state; email addresses and token material are discarded."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    installed: bool
    authenticated: bool
    auth_mode: Literal["apiKey", "chatgpt", "amazonBedrock"] | None = None
    plan_type: str | None = None

    @model_validator(mode="after")
    def validate_state(self) -> Self:
        if self.authenticated != (self.auth_mode is not None):
            raise ValueError("Codex account authentication state is inconsistent")
        if not self.installed and self.authenticated:
            raise ValueError("an unavailable Codex runtime cannot be authenticated")
        if self.plan_type is not None and (not self.plan_type or len(self.plan_type) > 100):
            raise ValueError("Codex plan type must be a bounded non-empty string")
        return self


class CodexToolArguments(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    destination: str | None


class CodexToolCall(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    call_id: UUID
    tool_name: str = Field(min_length=1, max_length=200)
    arguments: CodexToolArguments


class CodexStructuredOutput(BaseModel):
    """Flat Structured Outputs wire model; conversion enforces semantic union rules."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    response_type: Literal["final", "tool_calls"]
    summary: str | None
    diagnosis_strength: DiagnosisStrength | None
    evidence_ids: tuple[UUID, ...]
    limitations: tuple[str, ...]
    tool_calls: tuple[CodexToolCall, ...]

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.response_type == "final":
            if self.summary is None or self.diagnosis_strength is None or self.tool_calls:
                raise ValueError("Codex final response fields are inconsistent")
        elif (
            not self.tool_calls
            or self.summary is not None
            or self.diagnosis_strength is not None
            or self.evidence_ids
            or self.limitations
        ):
            raise ValueError("Codex tool-call response fields are inconsistent")
        return self

    def to_provider_response(self) -> AIProviderResponse:
        if self.response_type == "final":
            return _PROVIDER_RESPONSE_ADAPTER.validate_python(
                {
                    "response_type": "final",
                    "summary": self.summary,
                    "diagnosis_strength": self.diagnosis_strength,
                    "evidence_ids": self.evidence_ids,
                    "limitations": self.limitations,
                }
            )
        return _PROVIDER_RESPONSE_ADAPTER.validate_python(
            {
                "response_type": "tool_calls",
                "tool_calls": [item.model_dump(mode="json") for item in self.tool_calls],
            }
        )
