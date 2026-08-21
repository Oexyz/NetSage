"""Typed provider-neutral AI boundary and deterministic fake provider."""

from netsage.ai.base import AIProvider, AIProviderError
from netsage.ai.context import AIContextBuilder, UnsafeAIContextError
from netsage.ai.fake import FakeAIProvider
from netsage.ai.models import (
    AIContext,
    AIDeviceContext,
    AIEvidence,
    AIFinalResponse,
    AIFinding,
    AIProviderResponse,
    AIToolArguments,
    AIToolCall,
    AIToolCallsResponse,
    AIToolParameter,
    AIToolParameterType,
    AIToolResult,
    AIToolResultStatus,
    StructuredTool,
)

__all__ = [
    "AIContext",
    "AIContextBuilder",
    "AIDeviceContext",
    "AIEvidence",
    "AIFinalResponse",
    "AIFinding",
    "AIProvider",
    "AIProviderError",
    "AIProviderResponse",
    "AIToolArguments",
    "AIToolCall",
    "AIToolCallsResponse",
    "AIToolParameter",
    "AIToolParameterType",
    "AIToolResult",
    "AIToolResultStatus",
    "FakeAIProvider",
    "StructuredTool",
    "UnsafeAIContextError",
]
