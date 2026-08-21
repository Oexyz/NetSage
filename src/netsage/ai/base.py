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

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        self.code = code


class AIProvider(ABC):
    async def initialize(self) -> None:
        """Prepare provider-local resources without accessing network devices."""

        return None

    async def close(self) -> None:
        """Release provider-local resources and secret references."""

        return None

    @abstractmethod
    async def generate(
        self,
        context: AIContext,
        *,
        tools: Sequence[StructuredTool],
        tool_results: Sequence[AIToolResult],
    ) -> AIProviderResponse: ...
