import pytest

from netsage.broker import (
    AuditResult,
    AuthorizationDeniedError,
    InMemoryAuditSink,
    InvalidToolArgumentsError,
    InvalidToolResultError,
    ToolBroker,
    ToolDefinition,
    ToolNotAllowedError,
    UnsupportedDeviceCapabilityError,
)
from netsage.inventory import Inventory
from netsage.models import Capability, CommandResult, DeviceRef
from netsage.policies import OperationClass


def make_inventory(*capabilities: Capability) -> Inventory:
    device = DeviceRef(
        name="hp-core-01",
        host="192.0.2.10",
        platform="aruba_aoscx",
        credential_ref="hp-readonly",
        capabilities=frozenset(capabilities),
    )
    return Inventory(devices={device.name: device})


async def interface_handler(arguments: dict[str, object]) -> CommandResult:
    return CommandResult(
        device=str(arguments["device"]),
        operation="get_interfaces",
        output={"interfaces": []},
    )


@pytest.mark.asyncio
async def test_broker_invokes_allowlisted_capability_and_audits_success() -> None:
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=make_inventory(Capability.INTERFACES),
        audit_sink=audit,
        user="operator",
        ai_provider="fake",
    )
    broker.register(
        ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
        interface_handler,
    )

    result = await broker.invoke("get_interfaces", {"device": "hp-core-01"})

    assert result.operation == "get_interfaces"
    assert result.content_trust == "untrusted_device_data"
    assert audit.events[0].result is AuditResult.SUCCESS
    assert audit.events[0].configuration_changed is False
    assert audit.events[0].credential_exposed is False


@pytest.mark.asyncio
async def test_broker_rejects_unknown_tool_and_records_denial() -> None:
    audit = InMemoryAuditSink()
    broker = ToolBroker(inventory=make_inventory(), audit_sink=audit)

    with pytest.raises(ToolNotAllowedError, match="not allowed"):
        await broker.invoke("ssh", {"device": "hp-core-01", "command": "show config"})

    assert audit.events[0].result is AuditResult.DENIED


def test_broker_rejects_generic_and_duplicate_registration() -> None:
    broker = ToolBroker()
    generic = ToolDefinition(name="ssh", capability=Capability.FACTS)
    with pytest.raises(ToolNotAllowedError, match="forbidden"):
        broker.register(generic, interface_handler)

    definition = ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES)
    broker.register(definition, interface_handler)
    with pytest.raises(ValueError, match="already registered"):
        broker.register(definition, interface_handler)


@pytest.mark.asyncio
async def test_broker_rejects_unknown_device_and_missing_device_argument() -> None:
    definition = ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES)
    broker = ToolBroker(inventory=make_inventory(Capability.INTERFACES))
    broker.register(definition, interface_handler)

    with pytest.raises(InvalidToolArgumentsError, match="Unknown device"):
        await broker.invoke("get_interfaces", {"device": "unknown"})
    with pytest.raises(InvalidToolArgumentsError, match="device argument"):
        await broker.invoke("get_interfaces", {})


@pytest.mark.asyncio
async def test_broker_rejects_unsupported_capability() -> None:
    broker = ToolBroker(inventory=make_inventory(Capability.FACTS))
    broker.register(
        ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
        interface_handler,
    )

    with pytest.raises(UnsupportedDeviceCapabilityError, match="does not support"):
        await broker.invoke("get_interfaces", {"device": "hp-core-01"})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "operation_class",
    [OperationClass.CONFIGURATION, OperationClass.DESTRUCTIVE],
)
async def test_observe_mode_denies_mutating_operations(
    operation_class: OperationClass,
) -> None:
    broker = ToolBroker(inventory=make_inventory(Capability.INTERFACES))
    broker.register(
        ToolDefinition(
            name="get_interfaces",
            capability=Capability.INTERFACES,
            operation_class=operation_class,
        ),
        interface_handler,
    )

    with pytest.raises(AuthorizationDeniedError, match="denied in observe mode"):
        await broker.invoke("get_interfaces", {"device": "hp-core-01"})


@pytest.mark.asyncio
async def test_broker_redacts_results_and_audit_arguments() -> None:
    secret = "do-not" + "-log-this"
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=make_inventory(Capability.INTERFACES),
        audit_sink=audit,
    )

    async def unsafe_handler(arguments: dict[str, object]) -> CommandResult:
        return CommandResult(
            device=str(arguments["device"]),
            operation="get_interfaces",
            output={"authorization": f"Bearer {secret}", "password": secret},
        )

    broker.register(
        ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
        unsafe_handler,
    )
    result = await broker.invoke("get_interfaces", {"device": "hp-core-01"})

    assert secret not in result.model_dump_json()
    assert secret not in audit.events[0].model_dump_json()


@pytest.mark.asyncio
async def test_broker_rejects_unexpected_arguments_without_audit_leak() -> None:
    secret = "credential" + "-must-not-be-audited"
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=make_inventory(Capability.INTERFACES),
        audit_sink=audit,
    )
    broker.register(
        ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
        interface_handler,
    )

    with pytest.raises(InvalidToolArgumentsError, match="unexpected"):
        await broker.invoke(
            "get_interfaces",
            {"device": "hp-core-01", "arbitrary": secret},
        )
    assert secret not in audit.events[0].model_dump_json()


@pytest.mark.asyncio
async def test_broker_rejects_mismatched_handler_result_and_audits_failure() -> None:
    audit = InMemoryAuditSink()
    broker = ToolBroker(
        inventory=make_inventory(Capability.INTERFACES),
        audit_sink=audit,
    )

    async def wrong_handler(arguments: dict[str, object]) -> CommandResult:
        return CommandResult(device=str(arguments["device"]), operation="wrong", output={})

    broker.register(
        ToolDefinition(name="get_interfaces", capability=Capability.INTERFACES),
        wrong_handler,
    )
    with pytest.raises(InvalidToolResultError, match="mismatched"):
        await broker.invoke("get_interfaces", {"device": "hp-core-01"})
    assert audit.events[0].result is AuditResult.FAILURE
