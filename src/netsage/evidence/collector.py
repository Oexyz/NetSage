"""Broker-only evidence collection with safe partial-failure modeling."""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID

from netsage.broker import ToolBroker
from netsage.evidence.factory import EvidenceFactory
from netsage.evidence.models import (
    EvidenceCollectionFailure,
    EvidenceEnvelope,
    EvidenceFailurePhase,
)
from netsage.evidence.store import EvidenceStore
from netsage.inventory import Inventory
from netsage.models import Capability


class EvidenceCollector:
    """Invoke structured Broker tools and store only normalized evidence."""

    def __init__(
        self,
        *,
        broker: ToolBroker,
        inventory: Inventory,
        factory: EvidenceFactory,
        store: EvidenceStore,
        driver: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._broker = broker
        self._inventory = inventory
        self._factory = factory
        self._store = store
        self._driver = driver
        self._clock = clock

    async def collect(
        self,
        *,
        investigation_id: UUID,
        device_id: str,
        operation: str,
        capability: Capability,
        arguments: Mapping[str, object] | None = None,
    ) -> EvidenceEnvelope | EvidenceCollectionFailure:
        extra_arguments = dict(arguments or {})
        if "device" in extra_arguments:
            raise ValueError("collector owns the device argument")
        broker_arguments: dict[str, object] = {"device": device_id, **extra_arguments}
        try:
            result = await self._broker.invoke(operation, broker_arguments)
        except Exception as error:
            return self._failure(
                investigation_id,
                device_id,
                operation,
                capability,
                EvidenceFailurePhase.BROKER,
                error,
                "structured broker collection failed",
            )
        try:
            device = self._inventory.get_device(device_id)
            evidence = self._factory.create(
                investigation_id=investigation_id,
                capability=capability,
                platform=device.platform,
                driver=self._driver,
                result=result,
            )
        except Exception as error:
            return self._failure(
                investigation_id,
                device_id,
                operation,
                capability,
                EvidenceFailurePhase.NORMALIZATION,
                error,
                "normalized evidence conversion failed",
            )
        try:
            self._store.add(evidence)
        except Exception as error:
            return self._failure(
                investigation_id,
                device_id,
                operation,
                capability,
                EvidenceFailurePhase.STORAGE,
                error,
                "evidence storage rejected the observation",
            )
        return evidence

    def _failure(
        self,
        investigation_id: UUID,
        device_id: str,
        operation: str,
        capability: Capability,
        phase: EvidenceFailurePhase,
        error: Exception,
        reason: str,
    ) -> EvidenceCollectionFailure:
        return EvidenceCollectionFailure(
            investigation_id=investigation_id,
            device_id=device_id,
            operation=operation,
            capability=capability,
            observed_at=self._clock(),
            phase=phase,
            error_type=type(error).__name__,
            reason=reason,
        )
