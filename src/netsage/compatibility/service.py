"""Trusted FortiOS compatibility composition over existing Broker operations."""

from collections.abc import Callable
from datetime import UTC, datetime

from netsage.broker import ToolBroker
from netsage.compatibility.models import (
    CompatibilityErrorCategory,
    FortiOSCompatibilityReport,
)
from netsage.compatibility.probe import (
    FortiOSCompatibilityProbe,
    failed_compatibility_report,
)
from netsage.credentials import (
    CredentialSecretStore,
    CredentialSecretUnavailableError,
    CredentialStoreError,
)
from netsage.drivers.fortios import FortiOSConnectionError, FortiOSHostKeyError
from netsage.history import SQLiteAuditSink
from netsage.models import Platform
from netsage.onboarding.runtime import FortiOSRuntimeFactory
from netsage.state import (
    LocalState,
    SSHHostIdentityChangedError,
    SSHHostTrustManager,
    SSHTrustError,
)
from netsage.tools import FortiOSToolSet


class FortiOSCompatibilityService:
    """Prepare one authorized inventory device and run a bounded semantic probe."""

    def __init__(
        self,
        *,
        state: LocalState,
        secrets: CredentialSecretStore,
        runtime: FortiOSRuntimeFactory | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._state = state
        self._clock = clock
        self._runtime = runtime or FortiOSRuntimeFactory(
            profiles=state.credentials,
            secrets=secrets,
            trust=SSHHostTrustManager(state.host_trust),
        )

    async def inspect(self, device_id: str) -> FortiOSCompatibilityReport:
        inventory = self._state.load_inventory()
        device = inventory.get_device(device_id)
        if device.platform is not Platform.FORTIOS:
            raise ValueError("Compatibility probe requires a FortiOS device")
        try:
            prepared = await self._runtime.prepare(device)
        except (CredentialSecretUnavailableError, CredentialStoreError):
            return failed_compatibility_report(
                device_id=device.name,
                category=CompatibilityErrorCategory.CREDENTIAL_UNAVAILABLE,
                clock=self._clock,
            )
        except (SSHHostIdentityChangedError, SSHTrustError, FortiOSHostKeyError):
            return failed_compatibility_report(
                device_id=device.name,
                category=CompatibilityErrorCategory.HOST_KEY_FAILED,
                clock=self._clock,
            )
        except FortiOSConnectionError:
            return failed_compatibility_report(
                device_id=device.name,
                category=CompatibilityErrorCategory.TRANSPORT_FAILED,
                clock=self._clock,
            )
        effective_device = device.model_copy(update={"capabilities": prepared.driver.capabilities})
        effective_inventory = inventory.model_copy(
            update={
                "devices": {
                    **inventory.devices,
                    effective_device.name: effective_device,
                }
            }
        )
        broker = ToolBroker(
            inventory=effective_inventory,
            redactor=prepared.redactor,
            audit_sink=SQLiteAuditSink(
                self._state.history,
                redactor=prepared.redactor,
            ),
            user="local-cli",
            ai_provider=None,
        )
        FortiOSToolSet({effective_device.name: prepared.driver}).register(broker)
        return await FortiOSCompatibilityProbe(
            broker=broker,
            device_id=effective_device.name,
            clock=self._clock,
        ).run()
