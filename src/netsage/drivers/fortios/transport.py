"""Trusted AsyncSSH transport for allowlisted FortiOS commands."""

from __future__ import annotations

import asyncio
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import asyncssh

from netsage.credentials import CredentialKind, CredentialProvider
from netsage.drivers.fortios.commands import FortiOSRequest, FortiOSSemanticRequest
from netsage.models import DeviceRef, Platform
from netsage.security import SecretRedactor

if TYPE_CHECKING:
    from netsage.drivers.fortios.catalog.execution_models import FortiOSCatalogInvocation

_ANSI_ESCAPE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_PAGER_MARKER = re.compile(r"(?i)--\s*more\s*--")
_PROMPT_PREFIX = r"(?:[^\s()#$]+(?:\s+\([^)]+\))?\s+)?[#$]"
_PROMPT_LINE = re.compile(rf"^{_PROMPT_PREFIX}\s*$")
_PERMISSION_FAILURE = re.compile(
    r"(?im)^(?:not permission|no permissions?|not entitled to run the command|"
    r"not permitted|not authorized|permission denied|insufficient permissions|"
    r"failed because you have no rights|.*\bno permissions?\b).*$"
)
_COMMAND_UNAVAILABLE = re.compile(
    r"(?im)^(?:command fail\.?\s*return code|command failed|command fail|unknown action|"
    r"parse error|command not found|object does not exist|not supported on this platform)\b"
)
_COMMAND_FAILURE = re.compile(r"(?im)^(?:error:|execution failed|invalid command)\b")


class FortiOSTransportError(RuntimeError):
    """Safe transport failure which never embeds credential or raw device data."""


class FortiOSConnectionError(FortiOSTransportError):
    pass


class FortiOSAuthenticationError(FortiOSTransportError):
    pass


class FortiOSHostKeyError(FortiOSTransportError):
    pass


class FortiOSCommandError(FortiOSTransportError):
    pass


class FortiOSPermissionDeniedError(FortiOSCommandError):
    pass


class FortiOSCommandUnavailableError(FortiOSCommandError):
    pass


class FortiOSCommandRejectedError(FortiOSCommandError):
    pass


class FortiOSCommandTimeoutError(FortiOSCommandError):
    pass


class FortiOSOutputLimitError(FortiOSCommandError):
    pass


@dataclass(frozen=True, slots=True, repr=False)
class SSHHostKeyPin:
    """An in-memory host-key pin; it contains no credential material."""

    algorithm: str
    fingerprint: str
    known_hosts_data: bytes


async def discover_ssh_host_key(
    host: str, port: int, *, timeout_seconds: float = 10.0
) -> SSHHostKeyPin:
    """Retrieve a host key without sending authentication credentials."""

    try:
        async with asyncio.timeout(timeout_seconds):
            key = await asyncssh.get_server_host_key(host, port, config=None)
    except (OSError, asyncssh.Error, TimeoutError) as error:
        raise FortiOSConnectionError("Unable to retrieve SSH host key") from error
    if key is None:
        raise FortiOSHostKeyError("SSH server did not present a host key")
    host_pattern = host if port == 22 else f"[{host}]:{port}"
    known_hosts_data = f"{host_pattern} {key.export_public_key().decode().strip()}\n".encode()
    return SSHHostKeyPin(
        algorithm=key.get_algorithm(),
        fingerprint=key.get_fingerprint("sha256"),
        known_hosts_data=known_hosts_data,
    )


class FortiOSSSHTransport:
    """Resolve credentials internally and execute only typed FortiOS requests."""

    def __init__(
        self,
        device: DeviceRef,
        credential_provider: CredentialProvider,
        *,
        known_hosts_data: bytes,
        connect_timeout_seconds: float = 10.0,
        command_timeout_seconds: float = 30.0,
        max_output_characters: int = 5_000_000,
    ) -> None:
        if device.platform is not Platform.FORTIOS:
            raise ValueError("FortiOS transport requires a FortiOS device")
        if not known_hosts_data:
            raise ValueError("SSH host-key pin is required")
        self._device = device
        self._credential_provider = credential_provider
        self._known_hosts_data = known_hosts_data
        self._connect_timeout_seconds = connect_timeout_seconds
        self._command_timeout_seconds = command_timeout_seconds
        self._max_output_characters = max_output_characters

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        if not requests:
            return ()
        rendered = tuple(request.render() for request in requests)
        return await self._execute_rendered(rendered)

    async def execute_semantic(
        self, requests: Sequence[FortiOSRequest | FortiOSSemanticRequest]
    ) -> tuple[str, ...]:
        """Execute only the fixed source-traceable semantic promotion enum."""

        if not requests:
            return ()
        try:
            rendered = tuple(request.render() for request in requests)
        except (KeyError, RuntimeError, ValueError) as error:
            raise FortiOSCommandError("FortiOS semantic request is invalid") from error
        return await self._execute_rendered(rendered)

    async def execute_catalog(self, request: FortiOSCatalogInvocation) -> str:
        """Execute only a manifest-promoted ID; never accept a caller command string."""

        from netsage.drivers.fortios.catalog.models import (
            FortiOSExecutionDisposition,
            FortiOSExecutionSupport,
        )
        from netsage.drivers.fortios.catalog.registry import (
            FortiOSCatalogError,
            FortiOSCommandRegistry,
        )
        from netsage.policies import OperationClass

        registry = FortiOSCommandRegistry()
        try:
            definition = registry.get(request.command_id)
            if (
                definition.command_class is not OperationClass.READ_ONLY
                or definition.execution_disposition is not FortiOSExecutionDisposition.EXECUTABLE
                or definition.execution_support is not FortiOSExecutionSupport.SANITIZED_TEXT
            ):
                raise FortiOSCommandError("FortiOS catalog command is not executable")
            rendered = registry.render(request.command_id, request.arguments)
        except FortiOSCommandError:
            raise
        except (FortiOSCatalogError, KeyError, ValueError) as error:
            raise FortiOSCommandError("FortiOS catalog request is invalid") from error
        (output,) = await self._execute_rendered((rendered,))
        return output

    async def _execute_rendered(self, rendered: Sequence[str]) -> tuple[str, ...]:
        credential = await self._credential_provider.resolve(str(self._device.credential_ref))
        if credential.kind is not CredentialKind.PASSWORD:
            raise FortiOSAuthenticationError("FortiOS SSH currently requires a password credential")
        if not credential.username or credential.secret is None:
            raise FortiOSAuthenticationError("FortiOS SSH credential is incomplete")
        redactor = SecretRedactor(known_secrets=(credential.secret,))

        try:
            connection = await asyncssh.connect(
                self._device.host,
                self._device.port,
                username=credential.username,
                password=credential.secret,
                known_hosts=self._known_hosts_data,
                client_keys=[],
                agent_path=None,
                config=None,
                connect_timeout=self._connect_timeout_seconds,
                login_timeout=self._connect_timeout_seconds,
                preferred_auth=("password", "keyboard-interactive"),
                host_based_auth=False,
                public_key_auth=False,
                gss_auth=False,
                gss_kex=False,
                disable_trivial_auth=True,
                keepalive_interval=10,
                keepalive_count_max=2,
            )
        except asyncssh.PermissionDenied as error:
            raise FortiOSAuthenticationError("FortiOS SSH authentication failed") from error
        except asyncssh.HostKeyNotVerifiable as error:
            raise FortiOSHostKeyError("FortiOS SSH host-key validation failed") from error
        except (OSError, asyncssh.Error, TimeoutError) as error:
            raise FortiOSConnectionError("FortiOS SSH connection failed") from error

        try:
            outputs = []
            for command in rendered:
                raw = await self._execute_command(connection, command)
                sanitized = redactor.redact_text(raw)
                if _PERMISSION_FAILURE.search(sanitized):
                    raise FortiOSPermissionDeniedError(
                        "FortiOS denied permission for an allowlisted command"
                    )
                if _COMMAND_UNAVAILABLE.search(sanitized):
                    raise FortiOSCommandUnavailableError(
                        "FortiOS does not expose an allowlisted command variant"
                    )
                if _COMMAND_FAILURE.search(sanitized):
                    raise FortiOSCommandRejectedError("FortiOS rejected an allowlisted command")
                outputs.append(_clean_shell_output(sanitized, command))
            return tuple(outputs)
        finally:
            connection.close()
            await connection.wait_closed()

    async def _execute_command(self, connection: asyncssh.SSHClientConnection, command: str) -> str:
        try:
            process = await connection.create_process(
                term_type="vt100",
                term_size=(200, 1000),
                encoding="utf-8",
                errors="replace",
            )
            async with asyncio.timeout(self._command_timeout_seconds):
                await self._read_until_prompt(process)
                process.stdin.write(f"{command}\n")
                await process.stdin.drain()
                stdout = await self._read_until_prompt(process, acknowledge_paging=True)
                process.stdin.write("exit\n")
                await process.stdin.drain()
        except TimeoutError as error:
            raise FortiOSCommandTimeoutError("FortiOS command execution timed out") from error
        except (OSError, asyncssh.Error) as error:
            raise FortiOSCommandError("FortiOS command execution failed") from error
        return stdout

    async def _read_until_prompt(
        self,
        process: asyncssh.SSHClientProcess[str],
        *,
        acknowledge_paging: bool = False,
    ) -> str:
        """Read one bounded shell response and advance FortiOS screen paging safely."""

        chunks: list[str] = []
        output_length = 0
        acknowledged_markers = 0
        while True:
            chunk = await process.stdout.read(4096)
            if not isinstance(chunk, str):
                raise FortiOSCommandError("FortiOS command returned unexpected binary output")
            if not chunk:
                raise FortiOSCommandError("FortiOS shell closed before returning a prompt")
            output_length += len(chunk)
            if output_length > self._max_output_characters:
                raise FortiOSOutputLimitError("FortiOS command output exceeded the safety limit")
            chunks.append(chunk)
            output = "".join(chunks)
            visible_output = _ANSI_ESCAPE.sub("", output).replace("\r\n", "\n").replace("\r", "\n")
            normalized = _normalize_terminal_output(output)
            if acknowledge_paging:
                marker_count = len(_PAGER_MARKER.findall(visible_output))
                while acknowledged_markers < marker_count:
                    process.stdin.write(" ")
                    await process.stdin.drain()
                    acknowledged_markers += 1
            if _ends_with_prompt(normalized):
                return output


def _clean_shell_output(raw: str, command: str) -> str:
    """Remove terminal control data, command echo, and prompts from sanitized output."""

    normalized = _normalize_terminal_output(raw)
    prompt_command = re.compile(
        rf"^{_PROMPT_PREFIX}\s+{re.escape(command)}(?P<rest>.*)$",
        re.IGNORECASE,
    )
    lines = []
    command_echo_found = False
    for line in normalized.splitlines():
        stripped = line.strip()
        if stripped in {"exit", ""}:
            continue
        if _PROMPT_LINE.fullmatch(stripped):
            match = prompt_command.match(stripped)
            if match:
                command_echo_found = True
                remainder = match.group("rest").strip()
                if remainder:
                    lines.append(remainder)
                continue
            continue
        if stripped == command:
            command_echo_found = True
            continue
        if prompt_command.match(stripped):
            command_echo_found = True
            continue
        if stripped.endswith(command):
            # Handle bare command echoes without surrounding whitespace (legacy prompt styles).
            command_echo_found = True
            continue
        if command_echo_found:
            lines.append(line.rstrip())
            continue

    if not command_echo_found:
        # Some FortiOS/SSH combinations do not echo the command at all.
        # Preserve all non-prompt output in that case, with a best-effort first
        # command-token drop to avoid trailing prompt artifacts.
        marker = normalized.find(command)
        if marker >= 0:
            normalized = normalized[marker + len(command) :]
        lines = []
        for line in normalized.splitlines():
            stripped = line.strip()
            if stripped in {"", "exit"}:
                continue
            if _PROMPT_LINE.fullmatch(stripped):
                continue
            lines.append(line.rstrip())
    return "\n".join(lines).strip()


def _normalize_terminal_output(raw: str) -> str:
    normalized = _ANSI_ESCAPE.sub("", raw).replace("\r\n", "\n").replace("\r", "\n")
    normalized = _PAGER_MARKER.sub("", normalized)
    return normalized.replace("\x08", "")


def _ends_with_prompt(output: str) -> bool:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    return bool(lines and _PROMPT_LINE.fullmatch(lines[-1]))
