"""Structured, auditable tool broker boundary."""

from collections.abc import Awaitable, Callable, Mapping

from netsage.models import CommandResult

ToolHandler = Callable[[Mapping[str, object]], Awaitable[CommandResult]]


class ToolBroker:
    """Allowlist structured read-only operations; never expose SSH or secrets."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolHandler] = {}

    def register(self, name: str, handler: ToolHandler) -> None:
        if name in self._tools:
            raise ValueError(f"Tool already registered: {name}")
        self._tools[name] = handler

    async def invoke(self, name: str, arguments: Mapping[str, object]) -> CommandResult:
        try:
            handler = self._tools[name]
        except KeyError as error:
            raise ValueError(f"Tool is not allowed: {name}") from error
        return await handler(arguments)
