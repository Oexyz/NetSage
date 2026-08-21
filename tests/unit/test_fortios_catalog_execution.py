import ast
import asyncio
import json
from collections import deque
from ipaddress import ip_address, ip_network
from pathlib import Path

import pytest

from netsage.broker import AuditResult, InMemoryAuditSink
from netsage.drivers.fortios import FortiOSCommand, FortiOSRequest
from netsage.drivers.fortios.catalog import (
    FortiOSArgumentDefinition,
    FortiOSArgumentKind,
    FortiOSCatalogErrorCode,
    FortiOSCatalogExecutionError,
    FortiOSCatalogExecutor,
    FortiOSCatalogInvocation,
    FortiOSCommandRegistry,
    FortiOSExecutionDisposition,
    FortiOSExecutionReason,
    load_manifest,
)
from netsage.drivers.fortios.transport import FortiOSCommandError
from netsage.models import DataTrust
from netsage.policies import OperationClass
from netsage.security import SecretRedactor

CANARY = "CATALOG_EXECUTION_CANARY_SECRET"
ZERO_ARGUMENT_COMMAND = "fortios.execute.cpu.show"
IP_ARGUMENT_COMMAND = "fortios.diagnose.clearpass.list.address"
INTEGER_ARGUMENT_COMMAND = "fortios.diagnose.endpoint.avatar.list.active"
PORT_ARGUMENT_COMMAND = "fortios.diagnose.poe.get-port-status"


class FakeCatalogTransport:
    def __init__(
        self,
        outputs: tuple[str, ...] = ("synthetic output",),
        *,
        delay: float = 0,
        error: Exception | None = None,
    ) -> None:
        self.outputs = deque(outputs)
        self.delay = delay
        self.error = error
        self.requests: list[FortiOSCatalogInvocation] = []

    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str:
        self.requests.append(request)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.error is not None:
            raise self.error
        if not self.outputs:
            raise AssertionError("No scripted catalog output")
        return self.outputs.popleft()


def executor(
    transport: FakeCatalogTransport | None = None,
    *,
    registry: FortiOSCommandRegistry | None = None,
    audit: InMemoryAuditSink | None = None,
    redactor: SecretRedactor | None = None,
    timeout: float = 1,
    output_limit: int = 1_000_000,
) -> FortiOSCatalogExecutor:
    return FortiOSCatalogExecutor(
        device_id="firewall-example",
        transport=transport,
        registry=registry,
        audit_sink=audit,
        redactor=redactor,
        timeout_seconds=timeout,
        max_output_characters=output_limit,
    )


@pytest.mark.asyncio
async def test_known_read_only_command_executes_as_sanitized_untrusted_text() -> None:
    transport = FakeCatalogTransport((f"status ok\x1b token={CANARY}",))
    audit = InMemoryAuditSink()
    result = await executor(
        transport,
        audit=audit,
        redactor=SecretRedactor(known_secrets=(CANARY,)),
    ).execute(ZERO_ARGUMENT_COMMAND)

    assert result.command_id == ZERO_ARGUMENT_COMMAND
    assert result.classification is OperationClass.READ_ONLY
    assert result.trust is DataTrust.UNTRUSTED_DEVICE_DATA
    assert result.output_type.value == "sanitized_text"
    assert CANARY not in result.sanitized_output
    assert "<REDACTED>" in result.sanitized_output
    assert "\x1b" not in result.sanitized_output
    assert result.persisted is False
    assert result.evidence_created is False
    assert result.ai_visible is False
    assert result.configuration_changed is False
    assert transport.requests[0].command_id == ZERO_ARGUMENT_COMMAND
    event = audit.events[0]
    assert event.tool == f"fortios_catalog:{ZERO_ARGUMENT_COMMAND}"
    assert event.result is AuditResult.SUCCESS
    assert event.safe_arguments["classification"] == "read_only"
    assert event.configuration_changed is False
    assert event.credential_exposed is False
    assert CANARY not in event.model_dump_json()


def test_dry_run_renders_without_transport_or_audit() -> None:
    audit = InMemoryAuditSink()
    plan = executor(audit=audit).dry_run(
        IP_ARGUMENT_COMMAND,
        {"ip": ip_address("192.0.2.20")},
    )

    assert plan.rendered_command.endswith("192.0.2.20")
    assert plan.authorization.allowed is True
    assert plan.ai_visible is False
    assert plan.configuration_changed is False
    assert audit.events == ()


def test_required_and_optional_arguments_are_supported() -> None:
    registry = _registry_with_optional_vdom()

    without_optional = executor(registry=registry).dry_run(ZERO_ARGUMENT_COMMAND)
    with_optional = executor(registry=registry).dry_run(
        ZERO_ARGUMENT_COMMAND,
        {"vdom": "root"},
    )

    assert without_optional.rendered_command == "execute cpu show"
    assert with_optional.rendered_command == "execute cpu show root"
    assert without_optional.optional_arguments == ("vdom",)


@pytest.mark.parametrize(
    ("command_id", "arguments"),
    [
        (IP_ARGUMENT_COMMAND, {}),
        (IP_ARGUMENT_COMMAND, {"ip": "not-an-ip"}),
        (INTEGER_ARGUMENT_COMMAND, {"number": "not-an-integer"}),
        (INTEGER_ARGUMENT_COMMAND, {"number": -1}),
        (PORT_ARGUMENT_COMMAND, {"port": 0}),
        (PORT_ARGUMENT_COMMAND, {"port": 65_536}),
        (IP_ARGUMENT_COMMAND, {"ip": "192.0.2.1", "unexpected": "value"}),
    ],
)
def test_invalid_and_missing_arguments_fail_closed(
    command_id: str,
    arguments: dict[str, object],
) -> None:
    with pytest.raises(FortiOSCatalogExecutionError) as caught:
        executor().dry_run(command_id, arguments)

    assert caught.value.code is FortiOSCatalogErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    "value",
    [
        "; execute reboot",
        "\nconfig system admin",
        "$(execute reboot)",
        "`execute reboot`",
        "| execute reboot",
        "& execute reboot",
    ],
)
def test_injection_values_never_render(value: str) -> None:
    with pytest.raises(FortiOSCatalogExecutionError) as caught:
        executor().dry_run(IP_ARGUMENT_COMMAND, {"ip": value})

    assert caught.value.code is FortiOSCatalogErrorCode.INVALID_ARGUMENT


@pytest.mark.parametrize(
    "command_id",
    [
        "fortios.config.system.interface",
        "fortios.execute.reboot",
        "fortios.execute.ping",
        "fortios.execute.traceroute",
    ],
)
def test_configuration_destructive_and_diagnostics_are_policy_denied(command_id: str) -> None:
    with pytest.raises(FortiOSCatalogExecutionError) as caught:
        executor().dry_run(command_id)

    assert caught.value.code is FortiOSCatalogErrorCode.POLICY_DENIED


def test_existing_reviewed_ping_and_traceroute_requests_are_preserved() -> None:
    assert FortiOSRequest(FortiOSCommand.PING, ip_address("192.0.2.1")).render() == (
        "execute ping 192.0.2.1"
    )
    assert (
        FortiOSRequest(
            FortiOSCommand.TRACEROUTE,
            ip_address("2001:db8::1"),
        ).render()
        == "execute traceroute 2001:db8::1"
    )


def test_unknown_and_interactive_commands_have_bounded_errors() -> None:
    with pytest.raises(FortiOSCatalogExecutionError) as unknown:
        executor().dry_run("fortios.execute.not-documented")
    interactive = next(
        definition
        for definition in load_manifest().definitions
        if definition.execution_reason is FortiOSExecutionReason.INTERACTIVE_UNSUPPORTED
    )
    with pytest.raises(FortiOSCatalogExecutionError) as denied:
        executor().dry_run(interactive.id)

    assert unknown.value.code is FortiOSCatalogErrorCode.UNKNOWN_COMMAND
    assert denied.value.code is FortiOSCatalogErrorCode.INTERACTIVE_UNSUPPORTED


@pytest.mark.asyncio
async def test_timeout_output_limit_and_transport_failure_are_bounded() -> None:
    with pytest.raises(FortiOSCatalogExecutionError) as timeout:
        await executor(FakeCatalogTransport(delay=0.05), timeout=0.001).execute(
            ZERO_ARGUMENT_COMMAND
        )
    with pytest.raises(FortiOSCatalogExecutionError) as output_limit:
        await executor(FakeCatalogTransport(("x" * 20,)), output_limit=10).execute(
            ZERO_ARGUMENT_COMMAND
        )
    with pytest.raises(FortiOSCatalogExecutionError) as transport:
        await executor(FakeCatalogTransport(error=FortiOSCommandError("raw canary"))).execute(
            ZERO_ARGUMENT_COMMAND
        )

    assert timeout.value.code is FortiOSCatalogErrorCode.TIMEOUT
    assert output_limit.value.code is FortiOSCatalogErrorCode.OUTPUT_LIMIT_EXCEEDED
    assert transport.value.code is FortiOSCatalogErrorCode.TRANSPORT_FAILED
    assert "raw canary" not in str(transport.value)


@pytest.mark.asyncio
async def test_output_redaction_and_audit_failures_are_bounded() -> None:
    class FailingRedactor(SecretRedactor):
        def redact_text(self, value: str) -> str:
            raise RuntimeError(value)

    class FailingAudit:
        def record(self, _event: object) -> None:
            raise RuntimeError(CANARY)

    with pytest.raises(FortiOSCatalogExecutionError) as redaction:
        await executor(FakeCatalogTransport(), redactor=FailingRedactor()).execute(
            ZERO_ARGUMENT_COMMAND
        )
    with pytest.raises(FortiOSCatalogExecutionError) as audit:
        await FortiOSCatalogExecutor(
            device_id="firewall-example",
            transport=FakeCatalogTransport(),
            audit_sink=FailingAudit(),  # type: ignore[arg-type]
        ).execute(ZERO_ARGUMENT_COMMAND)

    assert redaction.value.code is FortiOSCatalogErrorCode.OUTPUT_REDACTION_FAILED
    assert audit.value.code is FortiOSCatalogErrorCode.AUDIT_FAILED
    assert CANARY not in str(audit.value)


def test_mass_validation_covers_every_catalog_definition_and_read_only_disposition() -> None:
    registry = FortiOSCommandRegistry()
    manifest = registry.manifest
    read_only = [
        definition
        for definition in manifest.definitions
        if definition.command_class is OperationClass.READ_ONLY
    ]

    assert len(manifest.definitions) == 19_030
    assert len(read_only) == 1_049
    assert manifest.coverage.read_only_executable == 515
    assert manifest.coverage.read_only_requires_review == 362
    assert manifest.coverage.read_only_non_executable == 172
    assert (
        sum(
            definition.execution_disposition is FortiOSExecutionDisposition.EXECUTABLE
            for definition in read_only
        )
        == 515
    )
    assert all(definition.ai_visible is False for definition in manifest.definitions)
    assert all(
        definition.execution_disposition is not FortiOSExecutionDisposition.EXECUTABLE
        for definition in manifest.definitions
        if definition.command_class
        in {
            OperationClass.DIAGNOSTIC,
            OperationClass.CONFIGURATION,
            OperationClass.DESTRUCTIVE,
        }
    )
    assert all(
        definition.execution_disposition is not FortiOSExecutionDisposition.EXECUTABLE
        for definition in manifest.definitions
        if any(argument.sensitive for argument in definition.arguments)
    )
    for definition in read_only:
        if definition.execution_disposition is not FortiOSExecutionDisposition.EXECUTABLE:
            continue
        rendered = registry.render(
            definition.id,
            {
                argument.name: _sample_value(argument)
                for argument in definition.arguments
                if argument.required
            },
        )
        assert "\n" not in rendered
        assert "\r" not in rendered
        assert ";" not in rendered
        assert "`" not in rendered
        assert "$(" not in rendered


def _sample_value(argument: FortiOSArgumentDefinition) -> object:
    if argument.kind in {FortiOSArgumentKind.ENUM, FortiOSArgumentKind.BOOLEAN}:
        return argument.choices[0]
    if argument.kind is FortiOSArgumentKind.IP_ADDRESS:
        return ip_address("192.0.2.10")
    if argument.kind is FortiOSArgumentKind.IPV4_ADDRESS:
        return ip_address("192.0.2.10")
    if argument.kind is FortiOSArgumentKind.IPV6_ADDRESS:
        return ip_address("2001:db8::10")
    if argument.kind is FortiOSArgumentKind.NETWORK:
        return ip_network("192.0.2.0/24")
    if argument.kind in {FortiOSArgumentKind.INTEGER, FortiOSArgumentKind.POLICY_ID}:
        return max(0, argument.minimum or 0)
    if argument.kind is FortiOSArgumentKind.PORT:
        return max(1, argument.minimum or 1)
    if argument.kind is FortiOSArgumentKind.HOSTNAME:
        return "example.invalid"
    if argument.kind is FortiOSArgumentKind.INTERFACE:
        return "port1"
    if argument.kind is FortiOSArgumentKind.VDOM:
        return "root"
    if argument.kind is FortiOSArgumentKind.PROTOCOL:
        return "tcp"
    if argument.kind is FortiOSArgumentKind.MAC_ADDRESS:
        return "02:00:00:00:00:01"
    raise AssertionError(f"broad argument unexpectedly promoted: {argument.kind}")


def _registry_with_optional_vdom() -> FortiOSCommandRegistry:
    manifest = load_manifest()
    original = next(
        definition for definition in manifest.definitions if definition.id == ZERO_ARGUMENT_COMMAND
    )
    optional = FortiOSArgumentDefinition(
        name="vdom",
        placeholder="<vdom>",
        kind=FortiOSArgumentKind.VDOM,
        required=False,
    )
    updated = original.model_copy(
        update={
            "syntax": "execute cpu show <vdom>",
            "arguments": (optional,),
        }
    )
    definitions = tuple(
        updated if definition.id == ZERO_ARGUMENT_COMMAND else definition
        for definition in manifest.definitions
    )
    return FortiOSCommandRegistry(manifest.model_copy(update={"definitions": definitions}))


def test_json_result_contains_no_secret_or_ai_exposure() -> None:
    result = asyncio.run(
        executor(
            FakeCatalogTransport((f"Authorization: Bearer {CANARY}",)),
            redactor=SecretRedactor(known_secrets=(CANARY,)),
        ).execute(ZERO_ARGUMENT_COMMAND)
    )
    payload = result.model_dump_json()

    assert CANARY not in payload
    assert json.loads(payload)["ai_visible"] is False


def test_catalog_execution_package_exposes_no_raw_cli_function_names() -> None:
    root = (
        Path(__file__).resolve().parents[2] / "src" / "netsage" / "drivers" / "fortios" / "catalog"
    )
    function_names = {
        node.name
        for path in root.glob("*.py")
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
    }

    assert function_names.isdisjoint({"run_cli", "execute_command", "send_command", "raw_cli"})
