"""Typed provider-neutral AI context, tools, calls, and final responses."""

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from netsage.evidence import EvidencePayload
from netsage.investigations import DiagnosisStrength, FindingSeverity
from netsage.models import Capability, DataTrust, Platform
from netsage.policies import OperationClass


class AIDeviceContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str
    platform: Platform
    capabilities: tuple[Capability, ...]


class AIEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    evidence_id: UUID
    source_device: str
    operation: str
    capability: Capability
    observed_at: datetime
    trust: DataTrust
    payload: EvidencePayload

    @field_validator("trust")
    @classmethod
    def validate_trust(cls, value: DataTrust) -> DataTrust:
        if value is not DataTrust.UNTRUSTED_DEVICE_DATA:
            raise ValueError("AI evidence must remain untrusted device data")
        return value


class AIFinding(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    code: str
    title: str
    summary: str
    severity: FindingSeverity
    strength: DiagnosisStrength | None = None
    evidence_ids: tuple[UUID, ...]


class AIContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    user_request: str = Field(min_length=1, max_length=2000)
    device: AIDeviceContext
    evidence: tuple[AIEvidence, ...]
    deterministic_findings: tuple[AIFinding, ...]
    missing_evidence: tuple[str, ...]


class AIToolParameterType(StrEnum):
    IP_ADDRESS = "ip_address"


class AIToolParameter(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    parameter_type: AIToolParameterType
    required: bool = True


class StructuredTool(BaseModel):
    """A Broker-owned operation description exposed to providers."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str
    description: str
    capability: Capability
    operation_class: OperationClass
    parameters: tuple[AIToolParameter, ...] = ()


class AIToolArguments(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    destination: IPv4Address | IPv6Address | None = None


class AIToolCall(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    call_id: UUID
    tool_name: str
    arguments: AIToolArguments = Field(default_factory=AIToolArguments)


class AIToolResultStatus(StrEnum):
    SUCCESS = "success"
    TOOL_DENIED = "tool_denied"
    DEVICE_UNAVAILABLE = "device_unavailable"
    COLLECTION_FAILED = "collection_failed"
    INVALID_ARGUMENTS = "invalid_arguments"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    REPEATED_TOOL_CALL = "repeated_tool_call"


class AIToolResult(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    call_id: UUID
    tool_name: str
    status: AIToolResultStatus
    evidence: AIEvidence | None = None

    @model_validator(mode="after")
    def validate_result(self) -> Self:
        if self.status is AIToolResultStatus.SUCCESS and self.evidence is None:
            raise ValueError("successful AI tool result requires evidence")
        if self.status is not AIToolResultStatus.SUCCESS and self.evidence is not None:
            raise ValueError("failed AI tool result cannot contain evidence")
        return self


class AIFinalResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    response_type: Literal["final"] = "final"
    summary: str = Field(min_length=1, max_length=4000)
    diagnosis_strength: DiagnosisStrength
    evidence_ids: tuple[UUID, ...] = ()
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_evidence(self) -> Self:
        if self.diagnosis_strength is not DiagnosisStrength.INSUFFICIENT and not self.evidence_ids:
            raise ValueError("AI diagnosis strength requires evidence references")
        return self


class AIToolCallsResponse(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    response_type: Literal["tool_calls"] = "tool_calls"
    tool_calls: tuple[AIToolCall, ...]

    @field_validator("tool_calls")
    @classmethod
    def validate_calls(cls, value: tuple[AIToolCall, ...]) -> tuple[AIToolCall, ...]:
        if not value:
            raise ValueError("tool-call response cannot be empty")
        return value


AIProviderResponse = Annotated[
    AIFinalResponse | AIToolCallsResponse,
    Field(discriminator="response_type"),
]
