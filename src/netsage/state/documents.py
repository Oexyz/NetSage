"""Versioned non-secret application settings document."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class ApplicationSettingsDocument(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: Literal[1] = 1
