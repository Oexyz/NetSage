from collections.abc import Callable
from typing import Any

import pytest

from netsage.credentials import (
    Credential,
    CredentialKind,
    EphemeralCredentialProvider,
)
from netsage.drivers.fortios import (
    FortiOSAuthenticationError,
    FortiOSCommand,
    FortiOSCommandError,
    FortiOSRequest,
    FortiOSSemanticCommand,
    FortiOSSemanticRequest,
    FortiOSSSHTransport,
    discover_ssh_host_key,
)
from netsage.drivers.fortios import transport as transport_module
from netsage.drivers.fortios.catalog import FortiOSCatalogInvocation
from netsage.models import DeviceRef


def make_device() -> DeviceRef:
    return DeviceRef(
        name="fortigate-lab",
        host="192.0.2.1",
        port=22022,
        platform="fortios",
        credential_ref="ephemeral-live",
    )


class FakeReader:
    def __init__(self, chunks: list[str]) -> None:
        self.chunks = chunks

    def feed(self, chunk: str) -> None:
        self.chunks.append(chunk)

    async def read(self, _size: int) -> str:
        return self.chunks.pop(0) if self.chunks else ""


class FakeWriter:
    def __init__(self, on_write: Callable[[str], None]) -> None:
        self.writes: list[str] = []
        self._on_write = on_write

    def write(self, data: str) -> None:
        self.writes.append(data)
        self._on_write(data)

    async def drain(self) -> None:
        return None


class FakeProcess:
    def __init__(
        self,
        output: str,
        *,
        prompt: str = "fortigate-lab #",
        echo_command: bool = True,
    ) -> None:
        self.output = output
        self.prompt = prompt
        self.echo_command = echo_command
        self.stdout = FakeReader([f"{prompt}\r\n"])
        self.stdin = FakeWriter(self._handle_input)

    def _handle_input(self, input_data: str) -> None:
        command = input_data.strip()
        if not command or command == "exit":
            return
        echo = f"{self.prompt} {command}\r\n" if self.echo_command else ""
        self.stdout.feed(f"{echo}{self.output}\r\n{self.prompt}\r\n")


class FakeConnection:
    def __init__(
        self,
        output: str,
        *,
        prompt: str = "fortigate-lab #",
        echo_command: bool = True,
    ) -> None:
        self.output = output
        self.prompt = prompt
        self.echo_command = echo_command
        self.closed = False
        self.process: FakeProcess | None = None

    async def create_process(self, **_kwargs: object) -> FakeProcess:
        self.process = FakeProcess(
            self.output,
            prompt=self.prompt,
            echo_command=self.echo_command,
        )
        return self.process

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


@pytest.mark.asyncio
async def test_transport_resolves_credential_inside_boundary_and_redacts_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credential_value = "transient" + "-credential-value"
    connection = FakeConnection(f"Version: FortiGate-VM64 v7.4.5\nEcho: {credential_value}")
    captured: dict[str, Any] = {}

    async def connect(*args: object, **kwargs: object) -> FakeConnection:
        captured["args"] = args
        captured["kwargs"] = kwargs
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(
            username="readonly",
            secret=credential_value,
            kind=CredentialKind.PASSWORD,
        ),
    )
    transport = FortiOSSSHTransport(
        make_device(),
        provider,
        known_hosts_data=b"[192.0.2.1]:22022 ssh-rsa synthetic-key\n",
    )

    (output,) = await transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))

    assert credential_value not in output
    assert "<REDACTED>" in output
    assert connection.closed is True
    assert captured["kwargs"]["known_hosts"]
    assert captured["kwargs"]["client_keys"] == []
    assert captured["kwargs"]["public_key_auth"] is False
    assert captured["kwargs"]["disable_trivial_auth"] is True


@pytest.mark.asyncio
async def test_transport_rejects_incomplete_credentials() -> None:
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret=None, kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(
        make_device(), provider, known_hosts_data=b"synthetic known host"
    )
    with pytest.raises(FortiOSAuthenticationError, match="incomplete"):
        await transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))


@pytest.mark.asyncio
async def test_transport_turns_device_rejection_into_bounded_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection("Command fail. Return code -37")

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(
        make_device(), provider, known_hosts_data=b"synthetic known host"
    )
    with pytest.raises(FortiOSCommandError, match="rejected") as captured:
        await transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))
    assert "-37" not in str(captured.value)


@pytest.mark.asyncio
async def test_transport_cleans_prompt_and_command_echo_with_vdom_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(
        "config system interface\r\n"
        '    edit "port1"\r\n'
        "        set ip 192.0.2.1 255.255.255.0\r\n"
        '        set alias "CORE"\r\n'
        "    next\r\n"
        "end",
        prompt="forti-gateway (root) #",
    )

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")

    (output,) = await transport.execute((FortiOSRequest(FortiOSCommand.INTERFACE_CONFIGURATION),))

    assert "forti-gateway" not in output
    assert "show system interface" not in output
    assert "config system interface" in output


@pytest.mark.asyncio
async def test_transport_handles_output_without_command_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection(
        "Version: FortiGate-VM64 v7.4.5,build2702,240813\r\nHostname: fortigate-lab",
        prompt="forti-gateway (root) #",
        echo_command=False,
    )

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")

    (output,) = await transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))

    assert "forti-gateway" not in output
    assert "Version: FortiGate-VM64 v7.4.5,build2702,240813" in output


@pytest.mark.asyncio
async def test_transport_flags_denied_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    connection = FakeConnection(
        "Command failed because you have no permissions to execute this command.",
        prompt="forti-gateway #",
    )

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")
    with pytest.raises(FortiOSCommandError, match="rejected"):
        await transport.execute((FortiOSRequest(FortiOSCommand.SYSTEM_STATUS),))


@pytest.mark.asyncio
async def test_transport_advances_fortios_paging_without_configuration_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class PagedProcess:
        def __init__(self) -> None:
            self.stdout = FakeReader(["forti-gateway #\r\n"])
            self.stdin = FakeWriter(self._handle_input)
            self.pages = 0

        def _handle_input(self, input_data: str) -> None:
            if input_data.startswith("show system interface"):
                self.stdout.feed(
                    "forti-gateway # show system interface\r\n"
                    "config system interface\r\n"
                    '    edit "port1"\r\n'
                    "\x1b[7m--More--\x1b[0m"
                )
            elif input_data == " ":
                self.pages += 1
                if self.pages == 1:
                    self.stdout.feed(
                        "\r        set ip 192.0.2.1 255.255.255.0\r\n\x1b[7m--More--\x1b[0m"
                    )
                else:
                    self.stdout.feed("\r    next\r\nend\r\nforti-gateway #\r\n")

    class PagedConnection:
        def __init__(self) -> None:
            self.closed = False
            self.process = PagedProcess()

        async def create_process(self, **_kwargs: object) -> PagedProcess:
            return self.process

        def close(self) -> None:
            self.closed = True

        async def wait_closed(self) -> None:
            return None

    connection = PagedConnection()

    async def connect(*_args: object, **_kwargs: object) -> PagedConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")

    (output,) = await transport.execute((FortiOSRequest(FortiOSCommand.INTERFACE_CONFIGURATION),))

    assert output.startswith("config system interface")
    assert 'edit "port1"' in output
    assert "set ip 192.0.2.1 255.255.255.0" in output
    assert output.endswith("end")
    assert connection.process.pages == 2
    assert not any("config system console" in write for write in connection.process.stdin.writes)


@pytest.mark.asyncio
async def test_discovers_host_key_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeKey:
        def export_public_key(self) -> bytes:
            return b"ssh-rsa synthetic-key\n"

        def get_algorithm(self) -> str:
            return "ssh-rsa"

        def get_fingerprint(self, algorithm: str) -> str:
            assert algorithm == "sha256"
            return "SHA256:synthetic"

    async def get_server_host_key(*_args: object, **_kwargs: object) -> FakeKey:
        return FakeKey()

    monkeypatch.setattr(transport_module.asyncssh, "get_server_host_key", get_server_host_key)
    pin = await discover_ssh_host_key("192.0.2.1", 22022)
    assert pin.algorithm == "ssh-rsa"
    assert pin.fingerprint == "SHA256:synthetic"
    assert pin.known_hosts_data.startswith(b"[192.0.2.1]:22022 ")


def test_transport_requires_fortios_device_and_host_key() -> None:
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="test", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    with pytest.raises(ValueError, match="host-key"):
        FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"")
    wrong_device = make_device().model_copy(update={"platform": "aruba_aoscx"})
    with pytest.raises(ValueError, match="FortiOS device"):
        FortiOSSSHTransport(wrong_device, provider, known_hosts_data=b"known")


@pytest.mark.asyncio
async def test_transport_executes_only_promoted_catalog_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = FakeConnection("CPU status: synthetic")

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")

    output = await transport.execute_catalog(
        FortiOSCatalogInvocation(command_id="fortios.execute.cpu.show")
    )

    assert output == "CPU status: synthetic"
    assert any("execute cpu show" in write for write in connection.process.stdin.writes)


@pytest.mark.asyncio
async def test_transport_executes_only_fixed_semantic_catalog_promotions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ike_canary = "0123456789abcdef0123456789abcdef"
    connection = FakeConnection(f"list all ipsec tunnel in vd 0\nkey: {ike_canary}")

    async def connect(*_args: object, **_kwargs: object) -> FakeConnection:
        return connection

    monkeypatch.setattr(transport_module.asyncssh, "connect", connect)
    provider = EphemeralCredentialProvider(
        "ephemeral-live",
        Credential(username="readonly", secret="test-" + "only", kind=CredentialKind.PASSWORD),
    )
    transport = FortiOSSSHTransport(make_device(), provider, known_hosts_data=b"known")

    (output,) = await transport.execute_semantic(
        (FortiOSSemanticRequest(FortiOSSemanticCommand.IPSEC_TUNNELS),)
    )

    assert "list all ipsec tunnel in vd 0" in output
    assert ike_canary not in output
    assert any("diagnose vpn tunnel list" in write for write in connection.process.stdin.writes)
    with pytest.raises(ValueError):
        FortiOSSemanticCommand("show user supplied command")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "command_id",
    [
        "fortios.config.system.interface",
        "fortios.execute.reboot",
        "fortios.execute.ping",
        "fortios.execute.not-documented",
    ],
)
async def test_transport_defense_in_depth_rejects_non_promoted_catalog_ids(
    command_id: str,
) -> None:
    class NeverResolveProvider:
        async def resolve(self, _reference: str) -> Credential:
            raise AssertionError("credential resolution must not occur")

    transport = FortiOSSSHTransport(
        make_device(),
        NeverResolveProvider(),  # type: ignore[arg-type]
        known_hosts_data=b"known",
    )

    with pytest.raises(FortiOSCommandError, match="catalog"):
        await transport.execute_catalog(FortiOSCatalogInvocation(command_id=command_id))
