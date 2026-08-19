"""Shared validated data models."""

from pydantic import BaseModel, ConfigDict


class DeviceRef(BaseModel):
    """Non-secret reference to a managed device."""

    model_config = ConfigDict(frozen=True)

    name: str
    host: str
    platform: str
    credential_ref: str


class CommandResult(BaseModel):
    """Sanitized output returned by a read-only driver operation."""

    model_config = ConfigDict(frozen=True)

    device: str
    operation: str
    output: dict[str, object]
