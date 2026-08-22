"""Parse bounded FortiOS OSPF process and neighbor status."""

import re
from ipaddress import ip_address

from netsage.drivers.fortios.semantic.common import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
    bounded_tuple,
    parse_duration_seconds,
    require_recognizable_output,
)
from netsage.models import (
    FeatureState,
    OSPFNeighbor,
    OSPFNeighborState,
    OSPFStatus,
    SemanticParserMetadata,
    SemanticParserState,
)
from netsage.models.observability import MAX_ROUTING_NEIGHBORS

_NOT_CONFIGURED = re.compile(r"(?i)ospf.*(?:not configured|no configuration)")
_DISABLED = re.compile(r"(?i)ospf.*(?:disabled|not enabled|not running)")


def parse_ospf_status(
    device_id: str,
    status_output: str,
    neighbors_output: str,
    *,
    variant: str = "ospf-neighbor-all-v1",
) -> OSPFStatus:
    combined = "\n".join((status_output, neighbors_output)).strip()
    if not combined:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.EMPTY_OUTPUT,
            "FortiOS OSPF output was empty",
        )
    if _NOT_CONFIGURED.search(combined):
        return _feature_absent(device_id, FeatureState.NOT_CONFIGURED, variant)
    if _DISABLED.search(combined):
        return _feature_absent(device_id, FeatureState.DISABLED, variant)
    status_text = require_recognizable_output(status_output, "OSPF status")
    neighbors_text = require_recognizable_output(neighbors_output, "OSPF neighbors")
    identity = re.search(
        r"(?im)^\s*Routing Process\s+[\"']?ospf\s+(\d+)[\"']?\s+with ID\s+([^\s]+)",
        status_text,
    ) or re.search(r"(?im)^\s*OSPF Router.*?ID\s*\(?([^\s)]+)\)?", status_text)
    has_neighbor_header = re.search(r"(?im)^\s*Neighbor ID\s+Pri\s+State", neighbors_text)
    if identity is None and has_neighbor_header is None:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS OSPF output was not recognized",
        )
    process_match = re.search(
        r"(?im)^\s*OSPF process\s+(\d+)(?:\s*,\s*VRF\s+\d+)?\s*:",
        neighbors_text,
    )
    process_id: int | None = None
    router_text: str | None = None
    if identity is not None:
        if len(identity.groups()) == 2:
            process_id = int(identity.group(1))
            router_text = identity.group(2)
        else:
            router_text = identity.group(1)
    if process_id is None and process_match:
        process_id = int(process_match.group(1))
    try:
        router_id = ip_address(router_text) if router_text else None
    except ValueError:
        router_id = None
    neighbors, truncated = bounded_tuple(
        _neighbors(device_id, neighbors_text), MAX_ROUTING_NEIGHBORS
    )
    return OSPFStatus(
        device_id=device_id,
        enabled=True,
        feature_state=FeatureState.ENABLED,
        parser=_metadata(
            variant,
            partial=(
                router_id is None
                or any(item.state is OSPFNeighborState.UNKNOWN for item in neighbors)
            ),
        ),
        process_id=process_id,
        router_id=router_id,
        neighbors=neighbors,
        truncated=truncated,
    )


def _neighbors(device_id: str, output: str) -> tuple[OSPFNeighbor, ...]:
    results = []
    in_table = False
    for line in output.splitlines():
        if re.match(r"(?i)^\s*Neighbor ID\s+Pri\s+State\s+Dead Time", line):
            in_table = True
            continue
        if not in_table:
            continue
        row = re.match(
            r"^\s*(?P<neighbor>\S+)\s+(?P<priority>\d+)\s+"
            r"(?P<state>[A-Za-z0-9-]+)\s*/?\s*(?P<role>[A-Za-z-]+)?\s+"
            r"(?P<dead>\d+(?::\d+){1,2})\s+(?P<address>\S+)\s+(?P<interface>.+?)\s*$",
            line,
        )
        if row is None:
            continue
        try:
            neighbor_id = ip_address(row.group("neighbor"))
            priority = int(row.group("priority"))
            address = ip_address(row.group("address"))
        except ValueError:
            continue
        results.append(
            OSPFNeighbor(
                device_id=device_id,
                neighbor_id=neighbor_id,
                address=address,
                interface=row.group("interface").strip(),
                state=_state(row.group("state")),
                role=(row.group("role") or "").strip("-") or None,
                priority=priority,
                dead_time_seconds=parse_duration_seconds(row.group("dead")),
            )
        )
    return tuple(results)


def _feature_absent(
    device_id: str,
    feature_state: FeatureState,
    variant: str,
) -> OSPFStatus:
    return OSPFStatus(
        device_id=device_id,
        enabled=False,
        feature_state=feature_state,
        parser=_metadata(variant, partial=False),
    )


def _metadata(variant: str, *, partial: bool) -> SemanticParserMetadata:
    return SemanticParserMetadata(
        state=SemanticParserState.PARTIAL if partial else SemanticParserState.PARSED,
        variant=variant,
        attempted_variants=(variant,),
    )


def _state(value: str) -> OSPFNeighborState:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return {
        "full": OSPFNeighborState.FULL,
        "2way": OSPFNeighborState.TWO_WAY,
        "twoway": OSPFNeighborState.TWO_WAY,
        "exstart": OSPFNeighborState.EXSTART,
        "exchange": OSPFNeighborState.EXCHANGE,
        "loading": OSPFNeighborState.LOADING,
        "init": OSPFNeighborState.INIT,
        "attempt": OSPFNeighborState.ATTEMPT,
        "down": OSPFNeighborState.DOWN,
    }.get(normalized, OSPFNeighborState.UNKNOWN)
