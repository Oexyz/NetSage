"""Create trusted FortiOS runtimes from stored device, keyring, and SSH trust state."""

from collections.abc import Callable
from dataclasses import dataclass

from netsage.credentials import (
    Credential,
    CredentialProfileStore,
    CredentialProvider,
    CredentialSecretStore,
    EphemeralCredentialProvider,
    KeyringCredentialProvider,
)
from netsage.drivers.fortios import FortiOSDriver, FortiOSSSHTransport, SSHHostKeyPin
from netsage.models import DeviceRef, Platform
from netsage.security import SecretRedactor
from netsage.state import SSHHostTrustManager


@dataclass(frozen=True, slots=True, repr=False)
class PreparedFortiOSRuntime:
    device: DeviceRef
    driver: FortiOSDriver
    redactor: SecretRedactor


class FortiOSRuntimeFactory:
    """Verify host identity first, then resolve credentials inside the trusted boundary."""

    def __init__(
        self,
        *,
        profiles: CredentialProfileStore,
        secrets: CredentialSecretStore,
        trust: SSHHostTrustManager,
        driver_builder: Callable[[DeviceRef, SSHHostKeyPin, Credential], FortiOSDriver]
        | None = None,
    ) -> None:
        self._credential_provider: CredentialProvider = KeyringCredentialProvider(
            profiles,
            secrets,
        )
        self._trust = trust
        self._driver_builder = driver_builder or self._default_driver

    async def verify_host(self, device: DeviceRef) -> SSHHostKeyPin:
        if device.platform is not Platform.FORTIOS:
            raise ValueError("Only FortiOS devices are supported")
        if device.trust_ref is None:
            raise ValueError("Device has no SSH trust reference")
        return await self._trust.verify(
            name=device.trust_ref,
            host=device.host,
            port=device.port,
        )

    async def resolve_credential(self, device: DeviceRef) -> Credential:
        return await self._credential_provider.resolve(str(device.credential_ref))

    def build(
        self,
        device: DeviceRef,
        pin: SSHHostKeyPin,
        credential: Credential,
    ) -> PreparedFortiOSRuntime:
        redactor = SecretRedactor(
            known_secrets=(credential.secret,) if credential.secret is not None else ()
        )
        return PreparedFortiOSRuntime(
            device=device,
            driver=self._driver_builder(device, pin, credential),
            redactor=redactor,
        )

    @staticmethod
    def _default_driver(
        device: DeviceRef,
        pin: SSHHostKeyPin,
        credential: Credential,
    ) -> FortiOSDriver:
        reference = str(device.credential_ref)
        provider = EphemeralCredentialProvider(reference, credential)
        transport = FortiOSSSHTransport(
            device,
            provider,
            known_hosts_data=pin.known_hosts_data,
        )
        return FortiOSDriver(device.name, transport)

    async def prepare(self, device: DeviceRef) -> PreparedFortiOSRuntime:
        pin = await self.verify_host(device)
        credential = await self.resolve_credential(device)
        return self.build(device, pin, credential)

    async def prepare_with_reviewed_pin(
        self,
        device: DeviceRef,
        pin: SSHHostKeyPin,
    ) -> PreparedFortiOSRuntime:
        credential = await self.resolve_credential(device)
        return self.build(device, pin, credential)
