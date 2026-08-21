"""Strongly typed provider-neutral AI boundary."""

from abc import ABC, abstractmethod
from collections.abc import Sequence

from netsage.ai.models import (
    AIContext,
    AIProviderResponse,
    AIToolResult,
    StructuredTool,
)


class AIProviderError(RuntimeError):
    """Bounded provider failure without raw provider response or credentials."""


class AIProvider(ABC):
    @abstractmethod
    async def generate(
        self,
        context: AIContext,
        *,
        tools: Sequence[StructuredTool],
        tool_results: Sequence[AIToolResult],
    ) -> AIProviderResponse: ...
