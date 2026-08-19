"""Provider-neutral AI boundary."""

from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StructuredTool:
    """A broker-owned tool schema exposed to an AI provider."""

    name: str
    description: str
    input_schema: Mapping[str, object]


@dataclass(frozen=True, slots=True)
class AIResponse:
    """Provider-independent response without credential material."""

    text: str
    tool_calls: Sequence[Mapping[str, object]] = ()


class AIProvider(ABC):
    """Generate investigations using only sanitized context and structured tools."""

    @abstractmethod
    async def investigate(
        self, prompt: str, *, tools: Sequence[StructuredTool], context: Mapping[str, object]
    ) -> AIResponse: ...
