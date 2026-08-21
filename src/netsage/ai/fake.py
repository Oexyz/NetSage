"""Deterministic scripted provider for complete agent-loop tests."""

from collections import deque
from collections.abc import Sequence

from netsage.ai.base import AIProvider, AIProviderError
from netsage.ai.models import (
    AIContext,
    AIProviderResponse,
    AIToolResult,
    StructuredTool,
)


class FakeAIProvider(AIProvider):
    def __init__(self, responses: Sequence[AIProviderResponse | Exception]) -> None:
        self._responses = deque(responses)
        self.contexts: list[AIContext] = []
        self.tools: list[tuple[StructuredTool, ...]] = []
        self.tool_results: list[tuple[AIToolResult, ...]] = []

    async def generate(
        self,
        context: AIContext,
        *,
        tools: Sequence[StructuredTool],
        tool_results: Sequence[AIToolResult],
    ) -> AIProviderResponse:
        self.contexts.append(context)
        self.tools.append(tuple(tools))
        self.tool_results.append(tuple(tool_results))
        if not self._responses:
            raise AIProviderError("FakeAIProvider has no scripted response")
        response = self._responses.popleft()
        if isinstance(response, Exception):
            raise response
        return response
