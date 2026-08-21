"""Policy-controlled execution of promoted READ_ONLY FortiOS catalog IDs."""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from typing import cast

from pydantic import JsonValue, TypeAdapter, ValidationError

from netsage.broker import AuditEvent, AuditResult, AuditSink, InMemoryAuditSink
from netsage.drivers.fortios.catalog.execution_models import (
    FortiOSCatalogCommandResult,
    FortiOSCatalogDryRun,
    FortiOSCatalogErrorCode,
    FortiOSCatalogInvocation,
    FortiOSCatalogOutputType,
    FortiOSCatalogTransport,
)
from netsage.drivers.fortios.catalog.models import (
    FortiOSCommandDefinition,
    FortiOSExecutionDisposition,
    FortiOSExecutionReason,
    FortiOSParserSupport,
)
from netsage.drivers.fortios.catalog.registry import (
    FortiOSCommandArgumentError,
    FortiOSCommandRegistry,
    FortiOSCommandRenderError,
    UnknownFortiOSCommandError,
)
from netsage.drivers.fortios.transport import (
    FortiOSCommandTimeoutError,
    FortiOSOutputLimitError,
    FortiOSTransportError,
)
from netsage.policies import AuthorizationDecision, ObservePolicy
from netsage.security import SecretRedactor

_JSON_ARGUMENTS = TypeAdapter(dict[str, JsonValue])
_SAFE_COMMAND_ID = re.compile(r"^[a-z0-9][a-z0-9_.:-]{0,767}$")
_SAFE_ARGUMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SAFE_DEVICE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class FortiOSCatalogExecutionError(RuntimeError):
    """Bounded failure without rendered command, raw output, or transport details."""

    def __init__(
        self,
        code: FortiOSCatalogErrorCode,
        message: str,
        *,
        authorization: AuthorizationDecision | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.authorization = authorization or AuthorizationDecision(
            allowed=False,
            reason=code.value.lower(),
        )


class FortiOSCatalogExecutor:
    def __init__(
        self,
        *,
        device_id: str,
        transport: FortiOSCatalogTransport | None = None,
        registry: FortiOSCommandRegistry | None = None,
        policy: ObservePolicy | None = None,
        redactor: SecretRedactor | None = None,
        audit_sink: AuditSink | None = None,
        user: str = "local-cli",
        timeout_seconds: float = 35.0,
        max_output_characters: int = 1_000_000,
        clock: Callable[[], datetime] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if not _SAFE_DEVICE_ID.fullmatch(device_id):
            raise ValueError("catalog executor requires a logical device ID")
        if timeout_seconds <= 0:
            raise ValueError("catalog execution timeout must be positive")
        if max_output_characters < 1:
            raise ValueError("catalog output limit must be positive")
        self._device_id = device_id
        self._transport = transport
        self._registry = registry or FortiOSCommandRegistry()
        self._policy = policy or ObservePolicy()
        self._redactor = redactor or SecretRedactor()
        self._audit = audit_sink or InMemoryAuditSink()
        self._user = user
        self._timeout_seconds = timeout_seconds
        self._max_output_characters = max_output_characters
        self._clock = clock or (lambda: datetime.now(UTC))
        self._monotonic = monotonic

    def dry_run(
        self,
        command_id: str,
        arguments: Mapping[str, object] | None = None,
    ) -> FortiOSCatalogDryRun:
        definition, invocation, rendered, authorization = self._prepare(
            command_id,
            arguments or {},
        )
        required = tuple(argument.name for argument in definition.arguments if argument.required)
        optional = tuple(
            argument.name for argument in definition.arguments if not argument.required
        )
        return FortiOSCatalogDryRun(
            command_id=invocation.command_id,
            device_id=self._device_id,
            classification=definition.command_class,
            rendered_command=rendered,
            authorization=authorization,
            required_arguments=required,
            optional_arguments=optional,
            output_type=FortiOSCatalogOutputType.SANITIZED_TEXT,
        )

    async def execute(
        self,
        command_id: str,
        arguments: Mapping[str, object] | None = None,
    ) -> FortiOSCatalogCommandResult:
        started = self._monotonic()
        safe_arguments: dict[str, JsonValue] = {"command_id": command_id}
        authorization = AuthorizationDecision(allowed=False, reason="not evaluated")
        try:
            definition, invocation, _rendered, authorization = self._prepare(
                command_id,
                arguments or {},
            )
            safe_arguments = {
                "command_id": invocation.command_id,
                "classification": definition.command_class.value,
                "arguments": invocation.arguments,
            }
            if self._transport is None:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.TRANSPORT_FAILED,
                    "FortiOS catalog transport is unavailable.",
                    authorization=authorization,
                )
            try:
                async with asyncio.timeout(self._timeout_seconds):
                    output = await self._transport.execute_catalog(invocation)
            except TimeoutError as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.TIMEOUT,
                    "FortiOS catalog execution timed out.",
                    authorization=authorization,
                ) from error
            except FortiOSCommandTimeoutError as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.TIMEOUT,
                    "FortiOS catalog execution timed out.",
                    authorization=authorization,
                ) from error
            except FortiOSOutputLimitError as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.OUTPUT_LIMIT_EXCEEDED,
                    "FortiOS catalog output exceeded its safety limit.",
                    authorization=authorization,
                ) from error
            except FortiOSTransportError as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.TRANSPORT_FAILED,
                    "FortiOS catalog transport failed.",
                    authorization=authorization,
                ) from error
            except Exception as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.TRANSPORT_FAILED,
                    "FortiOS catalog transport failed.",
                    authorization=authorization,
                ) from error
            try:
                sanitized = self._redactor.redact_text(output)
            except Exception as error:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.OUTPUT_REDACTION_FAILED,
                    "FortiOS catalog output redaction failed.",
                    authorization=authorization,
                ) from error
            sanitized = _strip_terminal_controls(sanitized)
            if len(sanitized) > self._max_output_characters:
                raise FortiOSCatalogExecutionError(
                    FortiOSCatalogErrorCode.OUTPUT_LIMIT_EXCEEDED,
                    "FortiOS catalog output exceeded its safety limit.",
                    authorization=authorization,
                )
            duration_ms = (self._monotonic() - started) * 1000
            result = FortiOSCatalogCommandResult(
                command_id=invocation.command_id,
                device_id=self._device_id,
                classification=definition.command_class,
                executed_at=self._clock(),
                duration_ms=duration_ms,
                sanitized_output=sanitized,
            )
            self._record_audit(
                command_id=invocation.command_id,
                arguments=safe_arguments,
                result=AuditResult.SUCCESS,
                authorization=authorization,
                duration_ms=duration_ms,
                detail=None,
            )
            return result
        except FortiOSCatalogExecutionError as error:
            duration_ms = (self._monotonic() - started) * 1000
            self._record_audit(
                command_id=command_id,
                arguments=_argument_names_only(command_id, arguments or {}),
                result=(
                    AuditResult.DENIED
                    if error.code
                    in {
                        FortiOSCatalogErrorCode.UNKNOWN_COMMAND,
                        FortiOSCatalogErrorCode.NOT_EXECUTABLE,
                        FortiOSCatalogErrorCode.POLICY_DENIED,
                        FortiOSCatalogErrorCode.INTERACTIVE_UNSUPPORTED,
                    }
                    else AuditResult.FAILURE
                ),
                authorization=error.authorization,
                duration_ms=duration_ms,
                detail=error.code.value,
            )
            raise

    def _prepare(
        self,
        command_id: str,
        arguments: Mapping[str, object],
    ) -> tuple[
        FortiOSCommandDefinition,
        FortiOSCatalogInvocation,
        str,
        AuthorizationDecision,
    ]:
        try:
            definition = self._registry.get(command_id)
        except UnknownFortiOSCommandError as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.UNKNOWN_COMMAND,
                "Unknown FortiOS catalog command ID.",
            ) from error
        tool_name = f"fortios_catalog:{definition.id}"
        authorization = self._policy.authorize(tool_name, definition.command_class)
        if not authorization.allowed:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.POLICY_DENIED,
                "FortiOS catalog command is denied by Observe policy.",
                authorization=authorization,
            )
        if definition.execution_disposition is not FortiOSExecutionDisposition.EXECUTABLE:
            code = (
                FortiOSCatalogErrorCode.INTERACTIVE_UNSUPPORTED
                if definition.execution_reason is FortiOSExecutionReason.INTERACTIVE_UNSUPPORTED
                else FortiOSCatalogErrorCode.NOT_EXECUTABLE
            )
            raise FortiOSCatalogExecutionError(
                code,
                "FortiOS catalog command is not promoted for execution.",
                authorization=authorization,
            )
        if definition.parser_support is not FortiOSParserSupport.SANITIZED_TEXT:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.NOT_EXECUTABLE,
                "FortiOS catalog command has no approved output boundary.",
                authorization=authorization,
            )
        try:
            json_arguments = _JSON_ARGUMENTS.validate_python(_normalize_argument_values(arguments))
            invocation = FortiOSCatalogInvocation(
                command_id=definition.id,
                arguments=json_arguments,
            )
        except (ValidationError, ValueError) as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.INVALID_ARGUMENT,
                "FortiOS catalog arguments are invalid.",
                authorization=authorization,
            ) from error
        safe_payload = {"command_id": definition.id, "arguments": invocation.arguments}
        try:
            redacted_payload = self._redactor.redact(safe_payload)
        except Exception as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.OUTPUT_REDACTION_FAILED,
                "FortiOS catalog argument redaction failed.",
                authorization=authorization,
            ) from error
        if redacted_payload != safe_payload:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.INVALID_ARGUMENT,
                "FortiOS catalog arguments contain sensitive material.",
                authorization=authorization,
            )
        try:
            rendered = self._registry.render(definition.id, invocation.arguments)
        except FortiOSCommandArgumentError as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.INVALID_ARGUMENT,
                "FortiOS catalog arguments are invalid.",
                authorization=authorization,
            ) from error
        except FortiOSCommandRenderError as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.RENDER_FAILED,
                "FortiOS catalog rendering failed.",
                authorization=authorization,
            ) from error
        try:
            redacted_command = self._redactor.redact_text(rendered)
        except Exception as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.OUTPUT_REDACTION_FAILED,
                "FortiOS rendered command redaction failed.",
                authorization=authorization,
            ) from error
        if redacted_command != rendered:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.INVALID_ARGUMENT,
                "FortiOS rendered command contains sensitive material.",
                authorization=authorization,
            )
        return definition, invocation, rendered, authorization

    def _record_audit(
        self,
        *,
        command_id: str,
        arguments: Mapping[str, JsonValue],
        result: AuditResult,
        authorization: AuthorizationDecision,
        duration_ms: float,
        detail: str | None,
    ) -> None:
        try:
            self._audit.record(
                AuditEvent(
                    user=self._user,
                    ai_provider=None,
                    tool=f"fortios_catalog:{_safe_command_id(command_id)}",
                    device=self._device_id,
                    safe_arguments=dict(arguments),
                    result=result,
                    duration_ms=duration_ms,
                    authorization=authorization,
                    detail=detail,
                )
            )
        except Exception as error:
            raise FortiOSCatalogExecutionError(
                FortiOSCatalogErrorCode.AUDIT_FAILED,
                "FortiOS catalog audit recording failed.",
                authorization=authorization,
            ) from error


def _argument_names_only(
    command_id: str,
    arguments: Mapping[str, object],
) -> dict[str, JsonValue]:
    safe_id = _safe_command_id(command_id)
    return {
        "command_id": safe_id,
        "argument_names": cast(
            JsonValue,
            sorted(
                name if _SAFE_ARGUMENT_NAME.fullmatch(name) else "invalid-argument-name"
                for name in (str(value) for value in arguments)
            ),
        ),
    }


def _safe_command_id(command_id: str) -> str:
    return command_id if _SAFE_COMMAND_ID.fullmatch(command_id) else "invalid-command-id"


def _normalize_argument_values(arguments: Mapping[str, object]) -> dict[str, JsonValue]:
    normalized: dict[str, JsonValue] = {}
    for name, value in arguments.items():
        if isinstance(value, str | int | float | bool) or value is None:
            normalized[str(name)] = value
        elif isinstance(value, IPv4Address | IPv6Address | IPv4Network | IPv6Network):
            normalized[str(name)] = str(value)
        else:
            raise ValueError("FortiOS catalog argument value type is unsupported")
    return normalized


def _strip_terminal_controls(value: str) -> str:
    return "".join(
        character
        for character in value
        if character in {"\n", "\t"} or (ord(character) >= 32 and not 127 <= ord(character) <= 159)
    )
