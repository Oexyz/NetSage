"""Versioned non-secret application settings document."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, field_validator

OpenAIReasoningEffort = Literal["none", "minimal", "low", "medium", "high", "xhigh", "max"]
AIProviderChoice = Literal[
    "auto",
    "openai-codex",
    "codex-app-server",
    "openai-api",
    "openai",
]


class OpenAIProviderSettings(BaseModel):
    """Non-secret OpenAI API preferences; the API key lives only in OS keyring."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    model: str = "gpt-5.6-terra"
    reasoning_effort: OpenAIReasoningEffort = "medium"

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        if not value.strip() or len(value) > 200:
            raise ValueError("OpenAI model must be a non-empty bounded string")
        return value


class AISettings(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # "openai" remains accepted as the pre-native-OAuth compatibility value and
    # has the same behavior as auto. New state writes use one of the explicit IDs.
    provider: AIProviderChoice = "auto"
    openai: OpenAIProviderSettings = OpenAIProviderSettings()


class ApplicationSettingsDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
    ai: AISettings = AISettings()
