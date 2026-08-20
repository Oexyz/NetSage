from collections.abc import Sequence
from pathlib import Path
from typing import ClassVar

import pytest

from netsage.credentials import (
    Credential,
    CredentialProfileService,
    CredentialSecretStore,
    CredentialSecretUnavailableError,
)
from netsage.drivers.fortios import (
    FortiOSAuthenticationError,
    FortiOSCommand,
    FortiOSConnectionError,
    FortiOSDriver,
    FortiOSRequest,
    SSHHostKeyPin,
)
from netsage.investigations import InvestigationStatus, render_investigation_report
from netsage.models import DeviceRef
from netsage.onboarding import (
    DeviceOnboardingError,
    DeviceReadiness,
    FortiOSDeviceService,
    FortiOSRuntimeFactory,
)
from netsage.state import LocalState, SSHHostTrustManager, StatePaths

FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"
CANARY = "NETSAGE_CANARY_SECRET_DO_NOT_LEAK_PERSISTENT_WORKFLOW"


class MemorySecretStore(CredentialSecretStore):
    def __init__(self) -> None:
        self.values: dict[str, str] = {}

    def set_secret(self, profile_name: str, secret: str) -> None:
        self.values[profile_name] = secret

    def get_secret(self, profile_name: str) -> str:
        try:
            return self.values[profile_name]
        except KeyError as error:
            raise CredentialSecretUnavailableError("Credential secret unavailable") from error

    def delete_secret(self, profile_name: str, *, missing_ok: bool = False) -> None:
        if profile_name not in self.values and not missing_ok:
            raise CredentialSecretUnavailableError("Credential secret unavailable")
        self.values.pop(profile_name, None)


class FixtureTransport:
    outputs: ClassVar[dict[FortiOSCommand, str]] = {
        FortiOSCommand.SYSTEM_STATUS: "system_status.txt",
        FortiOSCommand.INTERFACE_CONFIGURATION: "interfaces_config.txt",
        FortiOSCommand.PHYSICAL_INTERFACES: "interfaces_physical.txt",
        FortiOSCommand.ROUTES: "routes.txt",
        FortiOSCommand.SYSTEM_HEALTH: "system_health.txt",
    }

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        return tuple(
            (FIXTURES / self.outputs[request.command]).read_text(encoding="utf-8")
            for request in requests
        )


class AuthenticationFailureTransport:
    async def execute(self, _requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        raise FortiOSAuthenticationError("FortiOS SSH authentication failed")


def host_pin(
    fingerprint: str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
) -> SSHHostKeyPin:
    return SSHHostKeyPin(
        algorithm="ssh-ed25519",
        fingerprint=fingerprint,
        known_hosts_data=b"192.0.2.10 ssh-ed25519 synthetic-public-key\n",
    )


def runtime_factory(
    state: LocalState,
    secrets: CredentialSecretStore,
    trust: SSHHostTrustManager,
    *,
    authentication_failure: bool = False,
) -> FortiOSRuntimeFactory:
    def build(device: DeviceRef, _pin: SSHHostKeyPin, _credential: Credential) -> FortiOSDriver:
        transport = (
            AuthenticationFailureTransport() if authentication_failure else FixtureTransport()
        )
        return FortiOSDriver(device.name, transport)

    return FortiOSRuntimeFactory(
        profiles=state.credentials,
        secrets=secrets,
        trust=trust,
        driver_builder=build,
    )


def create_profile(state: LocalState, secrets: CredentialSecretStore) -> None:
    CredentialProfileService(
        profiles=state.credentials,
        secrets=secrets,
        inventory=state.inventory,
    ).add_password_profile(
        name="fortigate-readonly",
        username="netsage-ro",
        secret=CANARY,
    )


@pytest.mark.asyncio
async def test_persistent_reload_device_test_investigation_and_report(tmp_path: Path) -> None:
    paths = StatePaths.from_root(tmp_path / "state")
    state = LocalState(paths)
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    pin = host_pin()

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return pin

    trust = SSHHostTrustManager(state.host_trust, discovery=discover)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(state, secrets, trust),
    )
    reviewed_pin = await service.discover_host_key(host="192.0.2.10", port=22)
    added = await service.add_device(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        credential_ref="fortigate-readonly",
        reviewed_pin=reviewed_pin,
    )
    assert added.readiness is DeviceReadiness.READY

    reloaded = LocalState(paths)
    reloaded_trust = SSHHostTrustManager(reloaded.host_trust, discovery=discover)
    reloaded_service = FortiOSDeviceService(
        state=reloaded,
        secrets=secrets,
        trust=reloaded_trust,
        runtime=runtime_factory(reloaded, secrets, reloaded_trust),
    )
    device = reloaded_service.list_devices()[0]
    assert device.name == "fortigate-example"
    assert str(device.credential_ref) == "fortigate-readonly"
    tested = await reloaded_service.test_device(device.name)
    assert tested.readiness is DeviceReadiness.READY
    assert tested.device_facts is not None
    assert tested.device_facts.vendor == "Fortinet"

    report = await reloaded_service.investigate(device.name)
    assert report.status is InvestigationStatus.HEALTHY
    rendered = render_investigation_report(report)
    assert "No configuration changes were made" in rendered
    assert CANARY not in rendered

    serialized_state = "".join(
        path.read_text(encoding="utf-8") for path in paths.root.glob("*.yaml")
    )
    assert CANARY not in serialized_state
    assert "password:" not in serialized_state.casefold()
    assert "secret:" not in serialized_state.casefold()


@pytest.mark.asyncio
async def test_failed_onboarding_leaves_no_device_or_trust_record(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    pin = host_pin()

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return pin

    trust = SSHHostTrustManager(state.host_trust, discovery=discover)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(
            state,
            secrets,
            trust,
            authentication_failure=True,
        ),
    )
    with pytest.raises(DeviceOnboardingError) as captured:
        await service.add_device(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            credential_ref="fortigate-readonly",
            reviewed_pin=pin,
        )
    assert captured.value.result.readiness is DeviceReadiness.AUTHENTICATION_FAILED
    assert state.inventory.load().devices == {}
    assert state.host_trust.load().hosts == {}


@pytest.mark.asyncio
async def test_missing_secret_and_host_key_change_do_not_delete_device(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    original = host_pin()

    async def original_discovery(_host: str, _port: int) -> SSHHostKeyPin:
        return original

    trust = SSHHostTrustManager(state.host_trust, discovery=original_discovery)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(state, secrets, trust),
    )
    await service.add_device(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        credential_ref="fortigate-readonly",
        reviewed_pin=original,
    )

    secrets.values.clear()
    missing_secret = await service.test_device("fortigate-example")
    assert missing_secret.readiness is DeviceReadiness.CREDENTIAL_UNAVAILABLE
    assert "fortigate-example" in state.inventory.load().devices

    secrets.values["fortigate-readonly"] = CANARY
    changed = host_pin("SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")

    async def changed_discovery(_host: str, _port: int) -> SSHHostKeyPin:
        return changed

    changed_trust = SSHHostTrustManager(state.host_trust, discovery=changed_discovery)
    changed_service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=changed_trust,
        runtime=runtime_factory(state, secrets, changed_trust),
    )
    changed_result = await changed_service.test_device("fortigate-example")
    assert changed_result.readiness is DeviceReadiness.HOST_KEY_ERROR
    assert state.host_trust.get("fortigate-example").fingerprint == original.fingerprint
    assert "fortigate-example" in state.inventory.load().devices


@pytest.mark.asyncio
async def test_list_show_and_remove_use_local_state_without_network(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    pin = host_pin()
    discovery_calls = 0

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        nonlocal discovery_calls
        discovery_calls += 1
        return pin

    trust = SSHHostTrustManager(state.host_trust, discovery=discover)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(state, secrets, trust),
    )
    await service.add_device(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        credential_ref="fortigate-readonly",
        reviewed_pin=pin,
    )
    discovery_calls = 0
    assert service.list_devices()[0].name == "fortigate-example"
    device, trust_record = service.show_device("fortigate-example")
    assert device.name == trust_record.name
    assert discovery_calls == 0

    service.remove_device("fortigate-example")
    assert state.inventory.load().devices == {}
    assert state.host_trust.load().hosts == {}
    assert "fortigate-readonly" in state.credentials.load().profiles
    assert "fortigate-readonly" in secrets.values


@pytest.mark.asyncio
async def test_offline_device_remains_configured(tmp_path: Path) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    original = host_pin()

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return original

    trust = SSHHostTrustManager(state.host_trust, discovery=discover)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(state, secrets, trust),
    )
    await service.add_device(
        name="fortigate-example",
        host="192.0.2.10",
        port=22,
        credential_ref="fortigate-readonly",
        reviewed_pin=original,
    )

    async def offline(_host: str, _port: int) -> SSHHostKeyPin:
        raise FortiOSConnectionError("Unable to retrieve SSH host key")

    offline_trust = SSHHostTrustManager(state.host_trust, discovery=offline)
    offline_service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=offline_trust,
        runtime=runtime_factory(state, secrets, offline_trust),
    )
    result = await offline_service.test_device("fortigate-example")
    assert result.readiness is DeviceReadiness.UNREACHABLE
    assert "fortigate-example" in state.inventory.load().devices


@pytest.mark.asyncio
async def test_inventory_write_failure_rolls_back_new_trust(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = LocalState(StatePaths.from_root(tmp_path / "state"))
    state.initialize()
    secrets = MemorySecretStore()
    create_profile(state, secrets)
    pin = host_pin()

    async def discover(_host: str, _port: int) -> SSHHostKeyPin:
        return pin

    trust = SSHHostTrustManager(state.host_trust, discovery=discover)
    service = FortiOSDeviceService(
        state=state,
        secrets=secrets,
        trust=trust,
        runtime=runtime_factory(state, secrets, trust),
    )

    def fail_add(_device: DeviceRef) -> None:
        raise OSError("synthetic inventory write failure")

    monkeypatch.setattr(state.inventory, "add", fail_add)
    with pytest.raises(OSError, match="synthetic inventory"):
        await service.add_device(
            name="fortigate-example",
            host="192.0.2.10",
            port=22,
            credential_ref="fortigate-readonly",
            reviewed_pin=pin,
        )
    assert state.host_trust.load().hosts == {}
    assert state.inventory.load().devices == {}
