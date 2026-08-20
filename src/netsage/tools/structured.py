"""Vendor-neutral Broker adapters for normalized NetworkDriver operations."""

from collections.abc import Mapping, Sequence
from ipaddress import ip_address

from pydantic import BaseModel, JsonValue

from netsage.broker import ToolBroker, ToolDefinition
from netsage.drivers import NetworkDriver
from netsage.models import Capability, CommandResult
from netsage.policies import OperationClass


class StructuredDriverToolSet:
    """Register semantic tools backed by an explicit device-to-driver map."""

    def __init__(self, drivers: Mapping[str, NetworkDriver]) -> None:
        self._drivers = dict(drivers)

    def register(self, broker: ToolBroker) -> None:
        broker.register(
            ToolDefinition(name="get_device_facts", capability=Capability.FACTS),
            self.get_device_facts,
        )
        broker.register(
            ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
            self.get_interfaces,
        )
        broker.register(
            ToolDefinition(name="get_vlans", capability=Capability.VLANS),
            self.get_vlans,
        )
        broker.register(
            ToolDefinition(name="get_arp_table", capability=Capability.ARP),
            self.get_arp_table,
        )
        broker.register(
            ToolDefinition(name="get_routes", capability=Capability.ROUTES),
            self.get_routes,
        )
        broker.register(
            ToolDefinition(name="get_system_health", capability=Capability.SYSTEM_HEALTH),
            self.get_system_health,
        )
        broker.register(
            ToolDefinition(name="get_firewall_policies", capability=Capability.FIREWALL),
            self.get_firewall_policies,
        )
        diagnostic_arguments = frozenset({"device", "destination"})
        broker.register(
            ToolDefinition(
                name="ping",
                capability=Capability.PING,
                operation_class=OperationClass.DIAGNOSTIC,
                required_arguments=diagnostic_arguments,
            ),
            self.ping,
        )
        broker.register(
            ToolDefinition(
                name="traceroute",
                capability=Capability.TRACEROUTE,
                operation_class=OperationClass.DIAGNOSTIC,
                required_arguments=diagnostic_arguments,
            ),
            self.traceroute,
        )

    async def get_device_facts(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._one("get_device_facts", arguments, await self._driver(arguments).get_facts())

    async def get_interfaces(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._many(
            "get_interfaces", arguments, await self._driver(arguments).get_interfaces()
        )

    async def get_vlans(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._many("get_vlans", arguments, await self._driver(arguments).get_vlans())

    async def get_arp_table(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._many("get_arp_table", arguments, await self._driver(arguments).get_arp_table())

    async def get_routes(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._many("get_routes", arguments, await self._driver(arguments).get_routes())

    async def get_system_health(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._one(
            "get_system_health", arguments, await self._driver(arguments).get_system_health()
        )

    async def get_firewall_policies(self, arguments: Mapping[str, object]) -> CommandResult:
        return self._many(
            "get_firewall_policies",
            arguments,
            await self._driver(arguments).get_firewall_policies(),
        )

    async def ping(self, arguments: Mapping[str, object]) -> CommandResult:
        destination = ip_address(self._destination(arguments))
        return self._one("ping", arguments, await self._driver(arguments).ping(destination))

    async def traceroute(self, arguments: Mapping[str, object]) -> CommandResult:
        destination = ip_address(self._destination(arguments))
        return self._one(
            "traceroute", arguments, await self._driver(arguments).traceroute(destination)
        )

    def _driver(self, arguments: Mapping[str, object]) -> NetworkDriver:
        device = arguments.get("device")
        if not isinstance(device, str):
            raise ValueError("device must be a string")
        try:
            return self._drivers[device]
        except KeyError as error:
            raise ValueError("No network driver is registered for device") from error

    @staticmethod
    def _destination(arguments: Mapping[str, object]) -> str:
        destination = arguments.get("destination")
        if not isinstance(destination, str):
            raise ValueError("destination must be an IP address string")
        return destination

    @staticmethod
    def _device(arguments: Mapping[str, object]) -> str:
        device = arguments["device"]
        if not isinstance(device, str):
            raise ValueError("device must be a string")
        return device

    def _one(
        self, operation: str, arguments: Mapping[str, object], model: BaseModel
    ) -> CommandResult:
        return CommandResult(
            device=self._device(arguments),
            operation=operation,
            output={"result": model.model_dump(mode="json")},
        )

    def _many(
        self,
        operation: str,
        arguments: Mapping[str, object],
        models: Sequence[BaseModel],
    ) -> CommandResult:
        results: list[JsonValue] = [model.model_dump(mode="json") for model in models]
        return CommandResult(
            device=self._device(arguments),
            operation=operation,
            output={"results": results},
        )
