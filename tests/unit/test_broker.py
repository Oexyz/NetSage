import pytest

from netsage.broker import ToolBroker
from netsage.models import CommandResult


@pytest.mark.asyncio
async def test_broker_invokes_allowlisted_tool() -> None:
    broker = ToolBroker()

    async def get_interfaces(arguments: dict[str, object]) -> CommandResult:
        return CommandResult(device=str(arguments["device"]), operation="get_interfaces", output={})

    broker.register("get_interfaces", get_interfaces)
    result = await broker.invoke("get_interfaces", {"device": "hp-core-01"})
    assert result.operation == "get_interfaces"


@pytest.mark.asyncio
async def test_broker_rejects_unknown_tool() -> None:
    with pytest.raises(ValueError, match="not allowed"):
        await ToolBroker().invoke("ssh", {"command": "show running-config"})


def test_broker_rejects_duplicate_registration() -> None:
    broker = ToolBroker()

    async def handler(arguments: dict[str, object]) -> CommandResult:
        return CommandResult(device="test", operation="test", output=arguments)

    broker.register("facts", handler)
    with pytest.raises(ValueError, match="already registered"):
        broker.register("facts", handler)
