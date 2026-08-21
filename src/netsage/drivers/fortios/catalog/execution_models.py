"""Secret-free contracts for ID-based FortiOS catalog execution."""

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from re import compile as compile_pattern
from typing import Literal, Protocol, Self

from pydantic import BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

from netsage.models import DataTrust
from netsage.policies import AuthorizationDecision, OperationClass

_REFERENCE = compile_pattern(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,767}$")


class FortiOSCatalogErrorCode(StrEnum):
    UNKNOWN_COMMAND = "UNKNOWN_COMMAND"
    NOT_EXECUTABLE = "NOT_EXECUTABLE"
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    RENDER_FAILED = "RENDER_FAILED"
    TRANSPORT_FAILED = "TRANSPORT_FAILED"
    OUTPUT_REDACTION_FAILED = "OUTPUT_REDACTION_FAILED"
    OUTPUT_LIMIT_EXCEEDED = "OUTPUT_LIMIT_EXCEEDED"
    INTERACTIVE_UNSUPPORTED = "INTERACTIVE_UNSUPPORTED"
    TIMEOUT = "TIMEOUT"
    AUDIT_FAILED = "AUDIT_FAILED"


class FortiOSCatalogOutputType(StrEnum):
    SANITIZED_TEXT = "sanitized_text"


class FortiOSCatalogInvocation(BaseModel):
    """Transport request containing only a trusted ID and named values."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    command_id: str
    arguments: dict[str, JsonValue] = Field(default_factory=dict)

    @field_validator("command_id")
    @classmethod
    def validate_command_id(cls, value: str) -> str:
        if not _REFERENCE.fullmatch(value):
            raise ValueError("FortiOS catalog command ID is invalid")
        return value

    @field_validator("arguments")
    @classmethod
    def validate_argument_names(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if any(not _REFERENCE.fullmatch(name) for name in value):
            raise ValueError("FortiOS catalog argument name is invalid")
        return value


class FortiOSCatalogDryRun(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    command_id: str
    device_id: str
    classification: OperationClass
    rendered_command: str
    authorization: AuthorizationDecision
    required_arguments: tuple[str, ...]
    optional_arguments: tuple[str, ...]
    output_type: FortiOSCatalogOutputType
    ai_visible: Literal[False] = False
    configuration_changed: Literal[False] = False


class FortiOSCatalogCommandResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    command_id: str
    device_id: str
    classification: OperationClass
    executed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float = Field(ge=0)
    output_type: FortiOSCatalogOutputType = FortiOSCatalogOutputType.SANITIZED_TEXT
    sanitized_output: str
    trust: DataTrust = DataTrust.UNTRUSTED_DEVICE_DATA
    ai_visible: Literal[False] = False
    persisted: Literal[False] = False
    evidence_created: Literal[False] = False
    configuration_changed: Literal[False] = False

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.classification is not OperationClass.READ_ONLY:
            raise ValueError("catalog result must be read-only")
        if self.executed_at.tzinfo is None or self.executed_at.utcoffset() is None:
            raise ValueError("catalog result timestamp must be timezone-aware")
        return self


class FortiOSCatalogTransport(Protocol):
    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str: ...


SafeCatalogArguments = Mapping[str, JsonValue]
