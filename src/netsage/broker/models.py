"""Typed broker definitions and secret-free audit events."""

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, model_validator

from netsage.models import Capability
from netsage.policies import AuthorizationDecision, OperationClass


class ToolDefinition(BaseModel):
    """A structured operation registered at the infrastructure boundary."""

    model_config = ConfigDict(frozen=True)

    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    capability: Capability
    operation_class: OperationClass = OperationClass.READ_ONLY
    ai_visible: bool = True
    required_arguments: frozenset[str] = frozenset({"device"})
    optional_arguments: frozenset[str] = frozenset()

    @model_validator(mode="after")
    def validate_arguments(self) -> Self:
        if "device" not in self.required_arguments:
            raise ValueError("device must be a required broker argument")
        overlap = self.required_arguments.intersection(self.optional_arguments)
        if overlap:
            raise ValueError("required and optional arguments must not overlap")
        return self

    @property
    def allowed_arguments(self) -> frozenset[str]:
        return self.required_arguments.union(self.optional_arguments)


class AuditResult(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    FAILURE = "failure"


class AuditEvent(BaseModel):
    """A bounded audit record that intentionally excludes tool output and secrets."""

    model_config = ConfigDict(frozen=True)

    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    user: str
    ai_provider: str | None
    tool: str
    device: str | None
    safe_arguments: dict[str, JsonValue]
    result: AuditResult
    duration_ms: float = Field(ge=0)
    authorization: AuthorizationDecision
    configuration_changed: Literal[False] = False
    credential_exposed: Literal[False] = False
    detail: str | None = None


class AuditSink(Protocol):
    def record(self, event: AuditEvent) -> None: ...


class InMemoryAuditSink:
    """Deterministic audit collector for tests and early integrations."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> tuple[AuditEvent, ...]:
        return tuple(self._events)

    def record(self, event: AuditEvent) -> None:
        self._events.append(event)


SafeArguments = Mapping[str, JsonValue]
