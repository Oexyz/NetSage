"""Sequential Broker-only FortiOS compatibility characterization."""

import hashlib
import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime

from pydantic import BaseModel, ValidationError

from netsage import __version__
from netsage.broker import (
    AuthorizationDeniedError,
    ToolBroker,
    UnsupportedDeviceCapabilityError,
)
from netsage.compatibility.models import (
    CapabilityObservationState,
    CompatibilityArea,
    CompatibilityAreaResult,
    CompatibilityErrorCategory,
    CompatibilityParserState,
    FortiOSCompatibilityReport,
    FortiOSVDOMContext,
    FortiOSVDOMMode,
    FortiOSVDOMProfile,
)
from netsage.drivers.fortios import (
    FortiOSAuthenticationError,
    FortiOSCommandTimeoutError,
    FortiOSCommandUnavailableError,
    FortiOSConnectionError,
    FortiOSHostKeyError,
    FortiOSOutputLimitError,
    FortiOSParseError,
    FortiOSPermissionDeniedError,
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
    FortiOSVariantExhaustedError,
    FortiOSVersion,
)
from netsage.models import (
    BGPStatus,
    Capability,
    CommandResult,
    DeviceFacts,
    FeatureState,
    FirewallPolicy,
    HAStatus,
    Interface,
    IPsecStatus,
    OSPFStatus,
    RouteSummary,
    SDWANStatus,
    SemanticParserState,
    SystemHealth,
)

MAX_COMPATIBILITY_OPERATIONS = 10

type ObservedValue = (
    DeviceFacts
    | SystemHealth
    | tuple[Interface, ...]
    | RouteSummary
    | tuple[FirewallPolicy, ...]
    | HAStatus
    | SDWANStatus
    | IPsecStatus
    | BGPStatus
    | OSPFStatus
)


@dataclass(frozen=True, slots=True)
class _OperationSpec:
    area: CompatibilityArea
    operation: str
    capability: Capability
    model: type[BaseModel]
    many: bool = False
    parser_variant: str = "normalized-v1"


@dataclass(frozen=True, slots=True)
class _Observation:
    spec: _OperationSpec
    state: CapabilityObservationState
    parser_state: CompatibilityParserState
    error_category: CompatibilityErrorCategory
    parser_variants: tuple[str, ...]
    value: ObservedValue | None = None


_SPECS = (
    _OperationSpec(
        CompatibilityArea.SYSTEM,
        "get_device_facts",
        Capability.FACTS,
        DeviceFacts,
        parser_variant="facts-v2",
    ),
    _OperationSpec(
        CompatibilityArea.SYSTEM,
        "get_system_health",
        Capability.SYSTEM_HEALTH,
        SystemHealth,
        parser_variant="system-health-v2",
    ),
    _OperationSpec(
        CompatibilityArea.INTERFACES,
        "get_interfaces",
        Capability.INTERFACES,
        Interface,
        many=True,
        parser_variant="interfaces-v2",
    ),
    _OperationSpec(
        CompatibilityArea.ROUTING,
        "get_route_summary",
        Capability.ROUTES,
        RouteSummary,
        parser_variant="route-summary-v1",
    ),
    _OperationSpec(
        CompatibilityArea.FIREWALL,
        "get_firewall_policies",
        Capability.FIREWALL,
        FirewallPolicy,
        many=True,
        parser_variant="firewall-policy-v2",
    ),
    _OperationSpec(CompatibilityArea.HA, "get_ha_status", Capability.HA, HAStatus),
    _OperationSpec(
        CompatibilityArea.SDWAN,
        "get_sdwan_status",
        Capability.SDWAN,
        SDWANStatus,
    ),
    _OperationSpec(
        CompatibilityArea.IPSEC,
        "get_ipsec_status",
        Capability.IPSEC,
        IPsecStatus,
    ),
    _OperationSpec(CompatibilityArea.BGP, "get_bgp_status", Capability.BGP, BGPStatus),
    _OperationSpec(
        CompatibilityArea.OSPF,
        "get_ospf_status",
        Capability.OSPF,
        OSPFStatus,
    ),
)

_FATAL_ERRORS = {
    CompatibilityErrorCategory.AUTHENTICATION_FAILED,
    CompatibilityErrorCategory.HOST_KEY_FAILED,
    CompatibilityErrorCategory.TRANSPORT_FAILED,
    CompatibilityErrorCategory.TIMEOUT,
    CompatibilityErrorCategory.OUTPUT_LIMIT,
}


class FortiOSCompatibilityProbe:
    """Answer observability compatibility, never network health."""

    def __init__(
        self,
        *,
        broker: ToolBroker,
        device_id: str,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if len(_SPECS) > MAX_COMPATIBILITY_OPERATIONS:
            raise ValueError("FortiOS compatibility operation limit exceeded")
        self._broker = broker
        self._device_id = device_id
        self._clock = clock

    async def run(self) -> FortiOSCompatibilityReport:
        observations: list[_Observation] = []
        facts: DeviceFacts | None = None
        for index, spec in enumerate(_SPECS):
            if spec.area in {CompatibilityArea.BGP, CompatibilityArea.OSPF} and facts is None:
                observations.append(self._missing_version(spec))
                continue
            observation = await self._observe(spec)
            observations.append(observation)
            if index == 0 and isinstance(observation.value, DeviceFacts):
                facts = observation.value
            if index == 0 and observation.error_category in _FATAL_ERRORS:
                observations.extend(
                    self._fatal_observation(item, observation.error_category) for item in _SPECS[1:]
                )
                break
        areas = tuple(self._aggregate(area, observations) for area in CompatibilityArea)
        firmware = _firmware(facts)
        model_family = _model_family(facts.model) if facts else None
        vdom = _vdom_profile(facts)
        fingerprint = _fingerprint(firmware, model_family, vdom, areas)
        return FortiOSCompatibilityReport(
            netsage_version=__version__,
            generated_at=self._clock(),
            device_id=self._device_id,
            firmware=firmware,
            model_family=model_family,
            vdom=vdom,
            areas=areas,
            fingerprint=fingerprint,
        )

    async def _observe(self, spec: _OperationSpec) -> _Observation:
        try:
            result = await self._broker.invoke(spec.operation, {"device": self._device_id})
            value = _validated_value(result, spec)
        except Exception as error:
            return _error_observation(spec, error)
        if isinstance(value, HAStatus | SDWANStatus | IPsecStatus | BGPStatus | OSPFStatus):
            state = _feature_state(value.feature_state, value.enabled)
            parser_state = _parser_state(value.parser.state)
            error_category = (
                CompatibilityErrorCategory.PARTIAL
                if state is CapabilityObservationState.PARTIAL
                or parser_state is CompatibilityParserState.PARTIAL
                or value.truncated
                else CompatibilityErrorCategory.NONE
            )
            if value.truncated:
                state = CapabilityObservationState.PARTIAL
                parser_state = CompatibilityParserState.PARTIAL
            variants = value.parser.attempted_variants or (value.parser.variant,)
            return _Observation(
                spec=spec,
                state=state,
                parser_state=parser_state,
                error_category=error_category,
                parser_variants=variants,
                value=value,
            )
        return _Observation(
            spec=spec,
            state=CapabilityObservationState.SUPPORTED,
            parser_state=CompatibilityParserState.PARSED,
            error_category=CompatibilityErrorCategory.NONE,
            parser_variants=(spec.parser_variant,),
            value=value,
        )

    @staticmethod
    def _aggregate(
        area: CompatibilityArea,
        observations: Sequence[_Observation],
    ) -> CompatibilityAreaResult:
        relevant = tuple(item for item in observations if item.spec.area is area)
        states = {item.state for item in relevant}
        errors = tuple(
            item.error_category
            for item in relevant
            if item.error_category is not CompatibilityErrorCategory.NONE
        )
        if len(relevant) > 1 and len(states) > 1:
            state = CapabilityObservationState.PARTIAL
            parser_state = CompatibilityParserState.PARTIAL
            error = CompatibilityErrorCategory.PARTIAL
        else:
            state = relevant[0].state
            parser_state = relevant[0].parser_state
            error = errors[0] if errors else CompatibilityErrorCategory.NONE
        variants = tuple(
            dict.fromkeys(
                variant for observation in relevant for variant in observation.parser_variants
            )
        )[:3]
        return CompatibilityAreaResult(
            area=area,
            operations=tuple(item.spec.operation for item in relevant),
            capabilities=tuple(dict.fromkeys(item.spec.capability for item in relevant)),
            state=state,
            parser_state=parser_state,
            parser_variants=variants,
            error_category=error,
        )

    @staticmethod
    def _fatal_observation(
        spec: _OperationSpec,
        category: CompatibilityErrorCategory,
    ) -> _Observation:
        return _Observation(
            spec=spec,
            state=CapabilityObservationState.UNAVAILABLE,
            parser_state=CompatibilityParserState.NOT_APPLICABLE,
            error_category=category,
            parser_variants=(),
        )

    @staticmethod
    def _missing_version(spec: _OperationSpec) -> _Observation:
        return _Observation(
            spec=spec,
            state=CapabilityObservationState.PARTIAL,
            parser_state=CompatibilityParserState.NOT_APPLICABLE,
            error_category=CompatibilityErrorCategory.PARTIAL,
            parser_variants=(),
        )


def failed_compatibility_report(
    *,
    device_id: str,
    category: CompatibilityErrorCategory,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> FortiOSCompatibilityReport:
    areas = tuple(
        CompatibilityAreaResult(
            area=area,
            operations=tuple(spec.operation for spec in _SPECS if spec.area is area),
            capabilities=tuple(
                dict.fromkeys(spec.capability for spec in _SPECS if spec.area is area)
            ),
            state=CapabilityObservationState.UNAVAILABLE,
            parser_state=CompatibilityParserState.NOT_APPLICABLE,
            error_category=category,
        )
        for area in CompatibilityArea
    )
    vdom = FortiOSVDOMProfile()
    return FortiOSCompatibilityReport(
        netsage_version=__version__,
        generated_at=clock(),
        device_id=device_id,
        areas=areas,
        vdom=vdom,
        fingerprint=_fingerprint(None, None, vdom, areas),
    )


def _validated_value(result: CommandResult, spec: _OperationSpec) -> ObservedValue:
    if spec.many:
        if set(result.output) != {"results"} or not isinstance(result.output["results"], list):
            raise ValueError("compatibility collection result shape is invalid")
        return tuple(spec.model.model_validate(item) for item in result.output["results"])  # type: ignore[return-value]
    if set(result.output) != {"result"}:
        raise ValueError("compatibility result shape is invalid")
    return spec.model.model_validate(result.output["result"])  # type: ignore[return-value]


def _error_observation(spec: _OperationSpec, error: Exception) -> _Observation:
    category, state, parser_state, variants = _categorized_error(error)
    return _Observation(
        spec=spec,
        state=state,
        parser_state=parser_state,
        error_category=category,
        parser_variants=variants,
    )


def _categorized_error(
    error: Exception,
) -> tuple[
    CompatibilityErrorCategory,
    CapabilityObservationState,
    CompatibilityParserState,
    tuple[str, ...],
]:
    if isinstance(error, FortiOSVariantExhaustedError):
        category = _semantic_error_category(error.category)
        return (
            category,
            _state_for_error(category),
            CompatibilityParserState.UNRECOGNIZED,
            error.attempted_variants,
        )
    if isinstance(error, FortiOSSemanticParseError):
        category = _semantic_error_category(error.category)
        return category, _state_for_error(category), CompatibilityParserState.UNRECOGNIZED, ()
    if isinstance(error, FortiOSPermissionDeniedError | AuthorizationDeniedError):
        return (
            CompatibilityErrorCategory.PERMISSION_DENIED,
            CapabilityObservationState.PERMISSION_DENIED,
            CompatibilityParserState.NOT_APPLICABLE,
            (),
        )
    if isinstance(error, FortiOSCommandUnavailableError | UnsupportedDeviceCapabilityError):
        return (
            CompatibilityErrorCategory.COMMAND_UNAVAILABLE,
            CapabilityObservationState.UNAVAILABLE,
            CompatibilityParserState.NOT_APPLICABLE,
            (),
        )
    if isinstance(error, FortiOSAuthenticationError):
        category = CompatibilityErrorCategory.AUTHENTICATION_FAILED
    elif isinstance(error, FortiOSHostKeyError):
        category = CompatibilityErrorCategory.HOST_KEY_FAILED
    elif isinstance(error, FortiOSCommandTimeoutError | TimeoutError):
        category = CompatibilityErrorCategory.TIMEOUT
    elif isinstance(error, FortiOSOutputLimitError):
        category = CompatibilityErrorCategory.OUTPUT_LIMIT
    elif isinstance(error, FortiOSConnectionError):
        category = CompatibilityErrorCategory.TRANSPORT_FAILED
    elif isinstance(error, FortiOSParseError | ValidationError | ValueError):
        category = CompatibilityErrorCategory.OUTPUT_UNRECOGNIZED
    else:
        category = CompatibilityErrorCategory.TRANSPORT_FAILED
    return (
        category,
        _state_for_error(category),
        CompatibilityParserState.UNRECOGNIZED,
        (),
    )


def _semantic_error_category(
    category: FortiOSSemanticErrorCategory,
) -> CompatibilityErrorCategory:
    return {
        FortiOSSemanticErrorCategory.EMPTY_OUTPUT: CompatibilityErrorCategory.EMPTY_OUTPUT,
        FortiOSSemanticErrorCategory.COMMAND_UNAVAILABLE: (
            CompatibilityErrorCategory.COMMAND_UNAVAILABLE
        ),
        FortiOSSemanticErrorCategory.PERMISSION_DENIED: (
            CompatibilityErrorCategory.PERMISSION_DENIED
        ),
        FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED: (
            CompatibilityErrorCategory.OUTPUT_UNRECOGNIZED
        ),
        FortiOSSemanticErrorCategory.MALFORMED: (CompatibilityErrorCategory.OUTPUT_UNRECOGNIZED),
        FortiOSSemanticErrorCategory.PARTIAL: CompatibilityErrorCategory.PARTIAL,
    }[category]


def _state_for_error(category: CompatibilityErrorCategory) -> CapabilityObservationState:
    if category is CompatibilityErrorCategory.PERMISSION_DENIED:
        return CapabilityObservationState.PERMISSION_DENIED
    if category in {
        CompatibilityErrorCategory.EMPTY_OUTPUT,
        CompatibilityErrorCategory.OUTPUT_UNRECOGNIZED,
    }:
        return CapabilityObservationState.OUTPUT_UNRECOGNIZED
    if category is CompatibilityErrorCategory.PARTIAL:
        return CapabilityObservationState.PARTIAL
    return CapabilityObservationState.UNAVAILABLE


def _feature_state(
    feature_state: FeatureState,
    enabled: bool | None,
) -> CapabilityObservationState:
    if feature_state is FeatureState.ENABLED or enabled is True:
        return CapabilityObservationState.ENABLED
    if feature_state is FeatureState.DISABLED:
        return CapabilityObservationState.DISABLED
    if feature_state is FeatureState.NOT_CONFIGURED:
        return CapabilityObservationState.NOT_CONFIGURED
    return CapabilityObservationState.PARTIAL


def _parser_state(state: SemanticParserState) -> CompatibilityParserState:
    return {
        SemanticParserState.PARSED: CompatibilityParserState.PARSED,
        SemanticParserState.PARTIAL: CompatibilityParserState.PARTIAL,
        SemanticParserState.UNRECOGNIZED: CompatibilityParserState.UNRECOGNIZED,
    }[state]


def _firmware(facts: DeviceFacts | None) -> FortiOSVersion | None:
    if facts is None:
        return None
    try:
        return FortiOSVersion.parse(
            facts.os_version,
            build=facts.os_build,
            branch_point=facts.branch_point,
            release=facts.release,
        )
    except ValueError:
        return None


def _model_family(model: str) -> str | None:
    match = re.match(
        r"(?i)^(FortiGate|FortiWiFi|FortiProxy|FortiWeb|FortiADC)-?([A-Za-z0-9]+)",
        model.strip(),
    )
    if match is None:
        return None
    product = {
        "fortigate": "FortiGate",
        "fortiwifi": "FortiWiFi",
        "fortiproxy": "FortiProxy",
        "fortiweb": "FortiWeb",
        "fortiadc": "FortiADC",
    }[match.group(1).casefold()]
    return f"{product}-{match.group(2)}"


def _vdom_profile(facts: DeviceFacts | None) -> FortiOSVDOMProfile:
    if facts is None:
        return FortiOSVDOMProfile()
    configuration = (facts.vdom_configuration or "").casefold()
    if "disable" in configuration:
        mode = FortiOSVDOMMode.SINGLE
    elif "enable" in configuration:
        mode = FortiOSVDOMMode.MULTI
    else:
        mode = FortiOSVDOMMode.UNKNOWN
    current = (facts.vdom or "").casefold()
    if current == "global":
        context = FortiOSVDOMContext.GLOBAL
    elif current == "root":
        context = FortiOSVDOMContext.ROOT
    elif current:
        context = FortiOSVDOMContext.SPECIFIC
    else:
        context = FortiOSVDOMContext.UNKNOWN
    return FortiOSVDOMProfile(mode=mode, context=context, maximum=facts.max_vdoms)


def _fingerprint(
    firmware: FortiOSVersion | None,
    model_family: str | None,
    vdom: FortiOSVDOMProfile,
    areas: Sequence[CompatibilityAreaResult],
) -> str:
    payload = {
        "schema": 1,
        "firmware": firmware.model_dump(mode="json") if firmware else None,
        "model_family": model_family,
        "vdom": vdom.model_dump(mode="json"),
        "areas": [
            {
                "area": item.area.value,
                "state": item.state.value,
                "parser": item.parser_state.value,
                "variants": item.parser_variants,
                "error": item.error_category.value,
            }
            for item in areas
        ],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()
