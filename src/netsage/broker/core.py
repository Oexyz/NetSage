"""Structured tool dispatch with inventory, policy, redaction, and audit checks."""

from collections.abc import Awaitable, Callable, Mapping
from time import perf_counter

from pydantic import JsonValue, TypeAdapter

from netsage.broker.models import (
    AuditEvent,
    AuditResult,
    AuditSink,
    InMemoryAuditSink,
    ToolDefinition,
)
from netsage.inventory import Inventory, UnknownDeviceError
from netsage.models import CommandResult
from netsage.policies import AuthorizationDecision, ObservePolicy
from netsage.security import SecretRedactor

ToolHandler = Callable[[Mapping[str, object]], Awaitable[CommandResult]]

_JSON_MAPPING = TypeAdapter(dict[str, JsonValue])
_FORBIDDEN_TOOL_NAMES = {"execute_cli_string", "run_arbitrary_command", "shell", "ssh"}


class BrokerError(ValueError):
    """Base class for rejected or invalid broker operations."""


class ToolNotAllowedError(BrokerError):
    pass


class InvalidToolArgumentsError(BrokerError):
    pass


class UnsupportedDeviceCapabilityError(BrokerError):
    pass


class AuthorizationDeniedError(BrokerError):
    pass


class InvalidToolResultError(BrokerError):
    pass


class ToolBroker:
    """Dispatch explicitly modeled operations; never expose SSH or credentials."""

    def __init__(
        self,
        *,
        inventory: Inventory | None = None,
        policy: ObservePolicy | None = None,
        audit_sink: AuditSink | None = None,
        redactor: SecretRedactor | None = None,
        user: str = "unknown",
        ai_provider: str | None = None,
    ) -> None:
        self._inventory = inventory or Inventory()
        self._policy = policy or ObservePolicy()
        self._audit_sink = audit_sink or InMemoryAuditSink()
        self._redactor = redactor or SecretRedactor()
        self._user = user
        self._ai_provider = ai_provider
        self._tools: dict[str, tuple[ToolDefinition, ToolHandler]] = {}

    def register(self, definition: ToolDefinition, handler: ToolHandler) -> None:
        if definition.name in _FORBIDDEN_TOOL_NAMES:
            raise ToolNotAllowedError(f"Generic tool is forbidden: {definition.name}")
        if definition.name in self._tools:
            raise ValueError(f"Tool already registered: {definition.name}")
        self._tools[definition.name] = (definition, handler)

    def tools_for_device(self, device_name: str) -> tuple[ToolDefinition, ...]:
        """Return only registered operations currently allowed for one device."""

        device = self._inventory.get_device(device_name)
        definitions = (
            definition
            for definition, _handler in self._tools.values()
            if definition.capability in device.capabilities
            and self._policy.authorize(definition.name, definition.operation_class).allowed
        )
        return tuple(sorted(definitions, key=lambda item: item.name))

    def ai_tools_for_device(self, device_name: str) -> tuple[ToolDefinition, ...]:
        """Return only explicitly AI-promoted semantic operations."""

        return tuple(
            definition for definition in self.tools_for_device(device_name) if definition.ai_visible
        )

    async def invoke(self, name: str, arguments: Mapping[str, object]) -> CommandResult:
        started = perf_counter()
        device_name = arguments.get("device")
        audit_device = device_name if isinstance(device_name, str) else None

        try:
            definition, handler = self._tools[name]
        except KeyError as error:
            decision = AuthorizationDecision(allowed=False, reason="tool is not registered")
            self._record(
                started,
                name,
                audit_device,
                {"device": audit_device} if audit_device is not None else {},
                AuditResult.DENIED,
                decision,
                "unknown tool",
            )
            raise ToolNotAllowedError(f"Tool is not allowed: {name}") from error

        if not isinstance(device_name, str) or not device_name:
            decision = AuthorizationDecision(allowed=False, reason="valid device argument required")
            self._record(
                started,
                name,
                None,
                {
                    key: value
                    for key, value in arguments.items()
                    if key in definition.allowed_arguments
                },
                AuditResult.DENIED,
                decision,
                "invalid arguments",
            )
            raise InvalidToolArgumentsError("A non-empty device argument is required")

        provided_arguments = frozenset(arguments)
        missing_arguments = definition.required_arguments.difference(provided_arguments)
        unexpected_arguments = provided_arguments.difference(definition.allowed_arguments)
        if missing_arguments or unexpected_arguments:
            decision = AuthorizationDecision(allowed=False, reason="tool arguments are invalid")
            self._record(
                started,
                name,
                device_name,
                {
                    key: value
                    for key, value in arguments.items()
                    if key in definition.allowed_arguments
                },
                AuditResult.DENIED,
                decision,
                "invalid arguments",
            )
            raise InvalidToolArgumentsError("Missing or unexpected tool arguments")

        try:
            device = self._inventory.get_device(device_name)
        except UnknownDeviceError as error:
            decision = AuthorizationDecision(allowed=False, reason="device is not in inventory")
            self._record(
                started,
                name,
                device_name,
                arguments,
                AuditResult.DENIED,
                decision,
                "unknown device",
            )
            raise InvalidToolArgumentsError(str(error)) from error

        if definition.capability not in device.capabilities:
            decision = AuthorizationDecision(
                allowed=False, reason="device capability is unsupported"
            )
            self._record(
                started,
                name,
                device_name,
                arguments,
                AuditResult.DENIED,
                decision,
                "unsupported capability",
            )
            raise UnsupportedDeviceCapabilityError(
                f"Device {device_name} does not support {definition.capability.value}"
            )

        decision = self._policy.authorize(name, definition.operation_class)
        if not decision.allowed:
            self._record(
                started,
                name,
                device_name,
                arguments,
                AuditResult.DENIED,
                decision,
                "policy denied",
            )
            raise AuthorizationDeniedError(decision.reason)

        try:
            result = await handler(arguments)
            if result.device != device_name or result.operation != name:
                raise InvalidToolResultError("Handler returned mismatched device or operation")
            sanitized = _JSON_MAPPING.validate_python(self._redactor.redact(result.output))
            result = result.model_copy(update={"output": sanitized})
        except Exception as error:
            self._record(
                started,
                name,
                device_name,
                arguments,
                AuditResult.FAILURE,
                decision,
                f"handler failed: {type(error).__name__}",
            )
            raise

        self._record(
            started,
            name,
            device_name,
            arguments,
            AuditResult.SUCCESS,
            decision,
            _success_detail(name, result.output),
        )
        return result

    def _record(
        self,
        started: float,
        tool: str,
        device: str | None,
        arguments: Mapping[str, object],
        result: AuditResult,
        decision: AuthorizationDecision,
        detail: str,
    ) -> None:
        safe_arguments = _JSON_MAPPING.validate_python(self._redactor.redact(arguments))
        self._audit_sink.record(
            AuditEvent(
                user=self._user,
                ai_provider=self._ai_provider,
                tool=tool,
                device=device,
                safe_arguments=safe_arguments,
                result=result,
                duration_ms=(perf_counter() - started) * 1000,
                authorization=decision,
                detail=detail,
            )
        )


def _success_detail(tool: str, output: Mapping[str, object]) -> str:
    """Return bounded result metadata without copying normalized or raw output."""

    payload = output.get("result")
    if not isinstance(payload, dict):
        return "completed"
    truncated = payload.get("truncated") is True
    if tool == "get_ha_history":
        events = payload.get("events")
        event_count = len(events) if isinstance(events, list) else 0
        return f"completed; event_count={event_count}; truncated={str(truncated).lower()}"
    if tool == "get_ha_checksum_nonsync":
        mismatch_count = payload.get("mismatch_count")
        safe_count = mismatch_count if isinstance(mismatch_count, int) else 0
        return f"completed; mismatch_count={safe_count}; truncated={str(truncated).lower()}"
    return "completed"
