"""Convert redacted Broker results into typed evidence envelopes."""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, JsonValue, TypeAdapter

from netsage.evidence.models import (
    ArpEvidencePayload,
    DeviceFactsEvidencePayload,
    EvidenceEnvelope,
    EvidencePayload,
    EvidenceProvenance,
    FirewallPoliciesEvidencePayload,
    InterfacesEvidencePayload,
    PingEvidencePayload,
    RoutesEvidencePayload,
    SystemHealthEvidencePayload,
    TracerouteEvidencePayload,
    VlansEvidencePayload,
)
from netsage.models import (
    VLAN,
    ArpEntry,
    Capability,
    CommandResult,
    DataTrust,
    DeviceFacts,
    FirewallPolicy,
    Interface,
    PingResult,
    Platform,
    Route,
    SystemHealth,
    TracerouteResult,
)
from netsage.security import SecretRedactor

_JSON_MAPPING = TypeAdapter(dict[str, JsonValue])
_OPERATION_CAPABILITIES = {
    "get_device_facts": Capability.FACTS,
    "get_interfaces": Capability.INTERFACES,
    "get_vlans": Capability.VLANS,
    "get_arp_table": Capability.ARP,
    "get_routes": Capability.ROUTES,
    "get_system_health": Capability.SYSTEM_HEALTH,
    "get_firewall_policies": Capability.FIREWALL,
    "ping": Capability.PING,
    "traceroute": Capability.TRACEROUTE,
}


class EvidenceFactoryError(ValueError):
    """A bounded conversion error which never contains raw result data."""


class UnsupportedEvidenceOperationError(EvidenceFactoryError):
    pass


class InvalidEvidenceResultError(EvidenceFactoryError):
    pass


def _one[ModelT: BaseModel](output: Mapping[str, JsonValue], model: type[ModelT]) -> ModelT:
    if set(output) != {"result"}:
        raise InvalidEvidenceResultError("single-result operation returned an invalid shape")
    return model.model_validate(output["result"])


def _many[ModelT: BaseModel](
    output: Mapping[str, JsonValue], model: type[ModelT]
) -> tuple[ModelT, ...]:
    if set(output) != {"results"} or not isinstance(output["results"], list):
        raise InvalidEvidenceResultError("multi-result operation returned an invalid shape")
    return tuple(model.model_validate(item) for item in output["results"])


class EvidenceFactory:
    """Build immutable evidence only from structured, sanitized CommandResult data."""

    def __init__(
        self,
        *,
        redactor: SecretRedactor | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        evidence_id_factory: Callable[[], UUID] = uuid4,
    ) -> None:
        self._redactor = redactor or SecretRedactor()
        self._clock = clock
        self._evidence_id_factory = evidence_id_factory

    def create(
        self,
        *,
        investigation_id: UUID,
        capability: Capability,
        platform: Platform,
        driver: str,
        result: CommandResult,
    ) -> EvidenceEnvelope:
        expected_capability = _OPERATION_CAPABILITIES.get(result.operation)
        if expected_capability is None:
            raise UnsupportedEvidenceOperationError("operation has no evidence payload type")
        if expected_capability is not capability:
            raise InvalidEvidenceResultError("operation and capability do not match")
        if result.content_trust is not DataTrust.UNTRUSTED_DEVICE_DATA:
            raise InvalidEvidenceResultError(
                "broker result has an unsupported trust classification"
            )
        sanitized = _JSON_MAPPING.validate_python(self._redactor.redact(result.output))
        payload = self._payload(result.operation, sanitized)
        provenance = EvidenceProvenance(
            tool=result.operation,
            device_id=result.device,
            capability=capability,
            platform=platform,
            driver=driver,
        )
        return EvidenceEnvelope(
            evidence_id=self._evidence_id_factory(),
            investigation_id=investigation_id,
            device_id=result.device,
            operation=result.operation,
            capability=capability,
            observed_at=self._clock(),
            trust=result.content_trust,
            payload=payload,
            provenance=provenance,
        )

    @staticmethod
    def _payload(operation: str, output: Mapping[str, JsonValue]) -> EvidencePayload:
        if operation == "get_device_facts":
            return DeviceFactsEvidencePayload(facts=_one(output, DeviceFacts))
        if operation == "get_interfaces":
            return InterfacesEvidencePayload(interfaces=_many(output, Interface))
        if operation == "get_vlans":
            return VlansEvidencePayload(vlans=_many(output, VLAN))
        if operation == "get_arp_table":
            return ArpEvidencePayload(entries=_many(output, ArpEntry))
        if operation == "get_routes":
            return RoutesEvidencePayload(routes=_many(output, Route))
        if operation == "get_system_health":
            return SystemHealthEvidencePayload(health=_one(output, SystemHealth))
        if operation == "get_firewall_policies":
            return FirewallPoliciesEvidencePayload(policies=_many(output, FirewallPolicy))
        if operation == "ping":
            return PingEvidencePayload(result=_one(output, PingResult))
        if operation == "traceroute":
            return TracerouteEvidencePayload(result=_one(output, TracerouteResult))
        raise UnsupportedEvidenceOperationError("operation has no evidence payload type")
