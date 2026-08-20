"""CLI commands for secure local state, credentials, devices, and stored investigations."""

import asyncio

import typer
from rich.console import Console
from rich.table import Table

from netsage.credentials import (
    CredentialProfileInUseError,
    CredentialProfileNotFoundError,
    CredentialProfileService,
    CredentialSecretStore,
    CredentialStoreError,
    DuplicateCredentialProfileError,
    KeyringSecretStore,
)
from netsage.drivers.fortios import FortiOSParseError, FortiOSTransportError
from netsage.inventory import DuplicateDeviceError, UnknownDeviceError
from netsage.investigations import render_investigation_report
from netsage.onboarding import DeviceOnboardingError, DeviceTestResult, FortiOSDeviceService
from netsage.state import (
    DuplicateSSHTrustError,
    InvalidStateReferenceError,
    LocalState,
    SSHHostIdentityChangedError,
    SSHTrustError,
    StateError,
)

console = Console()
credentials_app = typer.Typer(
    name="credentials",
    help="Manage non-secret credential profiles and OS-keyring passwords.",
    no_args_is_help=True,
)
device_app = typer.Typer(
    name="device",
    help="Manage persistent FortiOS device profiles.",
    no_args_is_help=True,
)


def _state() -> LocalState:
    state = LocalState()
    state.initialize()
    return state


def _secrets() -> CredentialSecretStore:
    return KeyringSecretStore()


def _credential_service(state: LocalState) -> CredentialProfileService:
    return CredentialProfileService(
        profiles=state.credentials,
        secrets=_secrets(),
        inventory=state.inventory,
    )


def _device_service(state: LocalState) -> FortiOSDeviceService:
    return FortiOSDeviceService(state=state, secrets=_secrets())


def _fail(message: str, error: Exception) -> typer.Exit:
    console.print(f"[red]{message}[/red]")
    return typer.Exit(code=1)


def setup_state() -> None:
    """Initialize versioned, non-secret user-level state files."""

    try:
        state = _state()
    except StateError as error:
        raise _fail(str(error), error) from error
    console.print(f"NetSage state initialized: {state.paths.root}")
    console.print("No credentials or devices were created.")


@credentials_app.command("add")
def credential_add() -> None:
    """Create password metadata and store its secret in the OS credential store."""

    name = typer.prompt("Profile name")
    kind = typer.prompt("Credential type", default="password")
    if kind.casefold() != "password":
        raise _fail("Only password credentials are supported.", ValueError(kind))
    username = typer.prompt("Username")
    password = typer.prompt("Password", hide_input=True, confirmation_prompt=True)
    try:
        profile = _credential_service(_state()).add_password_profile(
            name=name,
            username=username,
            secret=password,
        )
    except (CredentialStoreError, StateError, DuplicateCredentialProfileError, ValueError) as error:
        raise _fail(str(error), error) from error
    finally:
        password = ""
    console.print(f"Credential profile created: {profile.name}")
    console.print("Secret storage: OS credential store")


@credentials_app.command("list")
def credential_list() -> None:
    """List credential metadata without reading any secret."""

    try:
        profiles = _state().credentials.load().profiles
    except StateError as error:
        raise _fail(str(error), error) from error
    table = Table(title="NetSage credential profiles")
    table.add_column("Name")
    table.add_column("Provider")
    table.add_column("Kind")
    table.add_column("Username")
    for name in sorted(profiles):
        profile = profiles[name]
        table.add_row(
            profile.name,
            profile.provider.value,
            profile.kind.value,
            profile.username,
        )
    console.print(table)


@credentials_app.command("show")
def credential_show(name: str) -> None:
    """Show profile metadata without resolving its secret."""

    try:
        profile = _state().credentials.get(name)
    except (StateError, CredentialProfileNotFoundError) as error:
        raise _fail(str(error), error) from error
    table = Table(title="Credential profile")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Name", profile.name)
    table.add_row("Provider", profile.provider.value)
    table.add_row("Kind", profile.kind.value)
    table.add_row("Username", profile.username)
    table.add_row("Secret", "stored securely")
    console.print(table)


@credentials_app.command("remove")
def credential_remove(name: str) -> None:
    """Remove an unreferenced profile and its OS-keyring secret."""

    if not typer.confirm(f"Remove credential profile {name}?", default=False):
        console.print("Credential removal cancelled.")
        raise typer.Exit(code=1)
    try:
        _credential_service(_state()).remove_profile(name)
    except (
        CredentialProfileInUseError,
        CredentialProfileNotFoundError,
        CredentialStoreError,
        StateError,
    ) as error:
        raise _fail(str(error), error) from error
    console.print(f"Credential profile removed: {name}")


def list_devices() -> None:
    """List stored device metadata without network or keyring access."""

    try:
        devices = _device_service(_state()).list_devices()
    except (StateError, InvalidStateReferenceError) as error:
        raise _fail(str(error), error) from error
    table = Table(title="NetSage devices")
    table.add_column("Name")
    table.add_column("Platform")
    table.add_column("Host")
    table.add_column("Port")
    table.add_column("Credential")
    for device in devices:
        table.add_row(
            device.name,
            device.platform.value,
            device.host,
            str(device.port),
            str(device.credential_ref),
        )
    console.print(table)


@device_app.command("add")
def device_add() -> None:
    """Trust, authenticate, verify, and then persist one FortiOS device."""

    name = typer.prompt("Device name")
    platform = typer.prompt("Platform", default="fortios")
    if platform.casefold() != "fortios":
        raise _fail("Only FortiOS devices are supported.", ValueError(platform))
    host = typer.prompt("Host")
    port = typer.prompt("SSH port", default=22, type=int)
    credential_ref = typer.prompt("Credential profile")
    state = _state()
    service = _device_service(state)
    try:
        state.credentials.get(credential_ref)
        pin = asyncio.run(service.discover_host_key(host=host, port=port))
    except (
        CredentialProfileNotFoundError,
        FortiOSTransportError,
        StateError,
        SSHTrustError,
        OSError,
    ) as error:
        raise _fail(str(error), error) from error
    console.print("SSH host key discovered")
    console.print(f"Device: {name}")
    console.print(f"Address: {host}:{port}")
    console.print(f"Algorithm: {pin.algorithm}")
    console.print(f"Fingerprint: {pin.fingerprint}")
    if not typer.confirm("Trust this host key?", default=False):
        console.print("Device was not saved.")
        raise typer.Exit(code=1)
    try:
        result = asyncio.run(
            service.add_device(
                name=name,
                host=host,
                port=port,
                credential_ref=credential_ref,
                reviewed_pin=pin,
            )
        )
    except (
        DeviceOnboardingError,
        DuplicateDeviceError,
        DuplicateSSHTrustError,
        StateError,
    ) as error:
        raise _fail(str(error), error) from error
    _print_device_test(result)
    console.print(f"Device saved: {name}")


@device_app.command("show")
def device_show(name: str) -> None:
    """Show stored device and trust metadata without connecting."""

    try:
        device, trust = _device_service(_state()).show_device(name)
    except (UnknownDeviceError, StateError, InvalidStateReferenceError, SSHTrustError) as error:
        raise _fail(str(error), error) from error
    table = Table(title="NetSage device")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("Name", device.name)
    table.add_row("Platform", device.platform.value)
    table.add_row("Host", device.host)
    table.add_row("Port", str(device.port))
    table.add_row("Credential Profile", str(device.credential_ref))
    table.add_row("Trust State", "stored")
    table.add_row("Host Key Algorithm", trust.algorithm)
    table.add_row("Host Key Fingerprint", trust.fingerprint)
    table.add_row("Site", device.site or "-")
    table.add_row("Groups", ", ".join(sorted(device.groups)) or "-")
    console.print(table)


@device_app.command("test")
def device_test(name: str) -> None:
    """Verify stored trust, credential, authentication, FortiOS, and facts."""

    try:
        result = asyncio.run(_device_service(_state()).test_device(name))
    except (UnknownDeviceError, StateError, InvalidStateReferenceError) as error:
        raise _fail(str(error), error) from error
    _print_device_test(result)
    if result.readiness.value != "ready":
        raise typer.Exit(code=1)


@device_app.command("remove")
def device_remove(name: str) -> None:
    """Remove local Inventory and trust state, but retain shared credentials."""

    if not typer.confirm(f"Remove device {name}?", default=False):
        console.print("Device removal cancelled.")
        raise typer.Exit(code=1)
    try:
        _device_service(_state()).remove_device(name)
    except (UnknownDeviceError, StateError) as error:
        raise _fail(str(error), error) from error
    console.print(f"Device removed: {name}")
    console.print("Credential profile retained.")


@device_app.command("trust-reset")
def device_trust_reset(name: str) -> None:
    """Explicitly review and replace a stored SSH host fingerprint."""

    state = _state()
    service = _device_service(state)
    try:
        device, pin = asyncio.run(service.discover_replacement_key(name))
        if device.trust_ref is None:
            raise ValueError("Device has no SSH trust reference")
        old = state.host_trust.get(device.trust_ref)
    except (
        FortiOSTransportError,
        UnknownDeviceError,
        StateError,
        SSHTrustError,
        ValueError,
    ) as error:
        raise _fail(str(error), error) from error
    console.print(f"Device: {device.name}")
    console.print(f"Expected: {old.algorithm} {old.fingerprint}")
    console.print(f"Received: {pin.algorithm} {pin.fingerprint}")
    if not typer.confirm("Replace the stored host-key trust?", default=False):
        console.print("SSH trust unchanged.")
        raise typer.Exit(code=1)
    try:
        service.replace_trust(device, pin)
    except (StateError, SSHTrustError) as error:
        raise _fail(str(error), error) from error
    console.print("SSH host-key trust updated.")


def investigate_device(name: str) -> None:
    """Run the existing deterministic investigation for a stored Device ID."""

    try:
        report = asyncio.run(_device_service(_state()).investigate(name))
    except (
        UnknownDeviceError,
        InvalidStateReferenceError,
        CredentialStoreError,
        FortiOSParseError,
        FortiOSTransportError,
        SSHHostIdentityChangedError,
        SSHTrustError,
        StateError,
        ValueError,
    ) as error:
        raise _fail(str(error), error) from error
    console.print(render_investigation_report(report))


def _print_device_test(result: DeviceTestResult) -> None:
    table = Table(title=f"Device test: {result.device_id}")
    table.add_column("Check")
    table.add_column("Status")
    table.add_row("Configured", result.configured.value.upper())
    table.add_row("Reachable", result.reachable.value.upper())
    table.add_row("Host key", result.host_key.value.upper())
    table.add_row("Credential", result.credential.value.upper())
    table.add_row("Authentication", result.authentication.value.upper())
    table.add_row("FortiOS", result.fortios.value.upper())
    table.add_row("Facts", result.facts.value.upper())
    console.print(table)
    if result.expected_host_key is not None:
        console.print(f"Expected: {result.expected_host_key}")
    if result.received_host_key is not None:
        console.print(f"Received: {result.received_host_key}")
    console.print(f"Result: {result.readiness.value.upper()}")
    console.print(result.detail)
