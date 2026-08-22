"""Convert redacted Broker results into typed evidence envelopes."""

from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from uuid import UUID, uuid4

from pydantic import BaseModel, JsonValue, TypeAdapter

from netsage.evidence.models import (
    ArpEvidencePayload,
    BGPNeighborsEvidencePayload,
    BGPStatusEvidencePayload,
    DeviceFactsEvidencePayload,
    EvidenceEnvelope,
    EvidencePayload,
    EvidenceProvenance,
    FirewallPoliciesEvidencePayload,
    HAMembersEvidencePayload,
    HAStatusEvidencePayload,
    InterfacesEvidencePayload,
    IPsecStatusEvidencePayload,
    IPsecTunnelsEvidencePayload,
    OSPFNeighborsEvidencePayload,
    OSPFStatusEvidencePayload,
    PingEvidencePayload,
    RoutesEvidencePayload,
    RouteSummaryEvidencePayload,
    SDWANHealthChecksEvidencePayload,
    SDWANMembersEvidencePayload,
    SDWANStatusEvidencePayload,
    SystemHealthEvidencePayload,
    TracerouteEvidencePayload,
    VlansEvidencePayload,
)
from netsage.models import (
    VLAN,
    ArpEntry,
    BGPNeighbor,
    BGPStatus,
    Capability,
    CommandResult,
    DataTrust,
    DeviceFacts,
    FirewallPolicy,
    HAMember,
    HAStatus,
    Interface,
    IPsecStatus,
    IPsecTunnel,
    OSPFNeighbor,
    OSPFStatus,
    PingResult,
    Platform,
    Route,
    RouteSummary,
    SDWANHealthCheck,
    SDWANMember,
    SDWANStatus,
    SemanticParserMetadata,
    SemanticParserState,
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
    "get_ha_status": Capability.HA,
    "get_ha_members": Capability.HA,
    "get_sdwan_status": Capability.SDWAN,
    "get_sdwan_members": Capability.SDWAN,
    "get_sdwan_health_checks": Capability.SDWAN,
    "get_ipsec_status": Capability.IPSEC,
    "get_ipsec_tunnels": Capability.IPSEC,
    "get_bgp_status": Capability.BGP,
    "get_bgp_neighbors": Capability.BGP,
    "get_ospf_status": Capability.OSPF,
    "get_ospf_neighbors": Capability.OSPF,
    "get_route_summary": Capability.ROUTES,
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
        parser_schema, parser_variant, parser_state = _parser_metadata(payload)
        provenance = EvidenceProvenance(
            tool=result.operation,
            device_id=result.device,
            capability=capability,
            platform=platform,
            driver=driver,
            parser_schema_version=parser_schema,
            parser_variant=parser_variant,
            parser_state=parser_state,
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
        if operation == "get_ha_status":
            return HAStatusEvidencePayload(status=_one(output, HAStatus))
        if operation == "get_ha_members":
            return HAMembersEvidencePayload(members=_many(output, HAMember))
        if operation == "get_sdwan_status":
            return SDWANStatusEvidencePayload(status=_one(output, SDWANStatus))
        if operation == "get_sdwan_members":
            return SDWANMembersEvidencePayload(members=_many(output, SDWANMember))
        if operation == "get_sdwan_health_checks":
            return SDWANHealthChecksEvidencePayload(health_checks=_many(output, SDWANHealthCheck))
        if operation == "get_ipsec_status":
            return IPsecStatusEvidencePayload(status=_one(output, IPsecStatus))
        if operation == "get_ipsec_tunnels":
            return IPsecTunnelsEvidencePayload(tunnels=_many(output, IPsecTunnel))
        if operation == "get_bgp_status":
            return BGPStatusEvidencePayload(status=_one(output, BGPStatus))
        if operation == "get_bgp_neighbors":
            return BGPNeighborsEvidencePayload(neighbors=_many(output, BGPNeighbor))
        if operation == "get_ospf_status":
            return OSPFStatusEvidencePayload(status=_one(output, OSPFStatus))
        if operation == "get_ospf_neighbors":
            return OSPFNeighborsEvidencePayload(neighbors=_many(output, OSPFNeighbor))
        if operation == "get_route_summary":
            return RouteSummaryEvidencePayload(summary=_one(output, RouteSummary))
        raise UnsupportedEvidenceOperationError("operation has no evidence payload type")


def _parser_metadata(
    payload: EvidencePayload,
) -> tuple[int, str, SemanticParserState]:
    parser: SemanticParserMetadata | None = None
    if isinstance(payload, HAStatusEvidencePayload):
        parser = payload.status.parser
    elif isinstance(payload, SDWANStatusEvidencePayload):
        parser = payload.status.parser
    elif isinstance(payload, IPsecStatusEvidencePayload):
        parser = payload.status.parser
    elif isinstance(payload, BGPStatusEvidencePayload):
        parser = payload.status.parser
    elif isinstance(payload, OSPFStatusEvidencePayload):
        parser = payload.status.parser
    if parser is None:
        return 1, "normalized-v1", SemanticParserState.PARSED
    return parser.schema_version, parser.variant, parser.state
