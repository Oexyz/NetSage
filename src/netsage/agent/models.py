"""Bounded agent runtime request, state, limits, and report models."""

from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from netsage.ai import AIFinalResponse, AIToolResult
from netsage.investigations import Finding


class AgentRuntimeState(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    WAITING_FOR_TOOL = "waiting_for_tool"
    COMPLETED = "completed"
    FAILED = "failed"
    LIMIT_REACHED = "limit_reached"


class AgentErrorCategory(StrEnum):
    PROVIDER_FAILED = "provider_failed"
    INVALID_RESPONSE = "invalid_response"
    INVALID_EVIDENCE_REFERENCE = "invalid_evidence_reference"
    DETERMINISTIC_CONTRADICTION = "deterministic_contradiction"
    REPEATED_TOOL_CALL = "repeated_tool_call"
    STEP_LIMIT_REACHED = "step_limit_reached"
    TOOL_LIMIT_REACHED = "tool_limit_reached"


class AgentRuntimeLimits(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_agent_steps: int = Field(default=8, ge=1, le=64)
    max_tool_calls_total: int = Field(default=20, ge=1, le=256)
    max_tool_calls_per_step: int = Field(default=4, ge=1, le=32)


class AgentInvestigationRequest(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    device_id: str = Field(min_length=1)
    question: str = Field(min_length=1, max_length=2000)


class AgentInvestigationReport(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    investigation_id: UUID
    device_id: str
    state: AgentRuntimeState
    deterministic_findings: tuple[Finding, ...]
    ai_assessment: AIFinalResponse | None = None
    tool_results: tuple[AIToolResult, ...] = ()
    error_category: AgentErrorCategory | None = None
    configuration_changed: Literal[False] = False
