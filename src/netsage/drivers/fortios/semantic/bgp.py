"""Parse bounded FortiOS BGP summary output."""

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
    BGPNeighbor,
    BGPSessionState,
    BGPStatus,
    FeatureState,
    SemanticParserMetadata,
    SemanticParserState,
)
from netsage.models.observability import MAX_ROUTING_NEIGHBORS

_NOT_CONFIGURED = re.compile(r"(?i)bgp.*(?:not configured|no configuration)")
_DISABLED = re.compile(r"(?i)bgp.*(?:disabled|not enabled|not running)")


def parse_bgp_status(
    device_id: str,
    output: str,
    *,
    variant: str = "bgp-summary-v1",
) -> BGPStatus:
    text = require_recognizable_output(output, "BGP summary")
    if _NOT_CONFIGURED.search(text):
        return _feature_absent(device_id, FeatureState.NOT_CONFIGURED, variant)
    if _DISABLED.search(text):
        return _feature_absent(device_id, FeatureState.DISABLED, variant)
    identity = re.search(
        r"(?im)^\s*BGP router identifier\s+([^,\s]+),\s*local AS number\s+(\d+)",
        text,
    )
    table = re.search(r"(?im)^\s*BGP table version is\s+(\d+)", text)
    has_header = re.search(r"(?im)^\s*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent", text)
    if identity is None and has_header is None:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS BGP summary output was not recognized",
        )
    neighbors, truncated = bounded_tuple(_neighbors(device_id, text), MAX_ROUTING_NEIGHBORS)
    try:
        router_id = ip_address(identity.group(1)) if identity else None
    except ValueError:
        router_id = None
    return BGPStatus(
        device_id=device_id,
        enabled=True,
        feature_state=FeatureState.ENABLED,
        parser=_metadata(
            variant,
            partial=(
                identity is None
                or any(neighbor.state is BGPSessionState.UNKNOWN for neighbor in neighbors)
            ),
        ),
        router_id=router_id,
        local_as=int(identity.group(2)) if identity else None,
        table_version=int(table.group(1)) if table else None,
        neighbors=neighbors,
        truncated=truncated,
    )


def parse_bgp_neighbors_status(
    device_id: str,
    output: str,
    *,
    variant: str = "bgp-neighbors-v1",
) -> BGPStatus:
    """Parse the reviewed detailed-neighbor fallback output."""

    text = require_recognizable_output(output, "BGP neighbors")
    if _NOT_CONFIGURED.search(text):
        return _feature_absent(device_id, FeatureState.NOT_CONFIGURED, variant)
    if _DISABLED.search(text):
        return _feature_absent(device_id, FeatureState.DISABLED, variant)
    blocks = _neighbor_blocks(text)
    if not blocks:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS BGP neighbor output was not recognized",
        )
    neighbors = []
    local_as: int | None = None
    for block in blocks:
        header = re.search(
            r"(?im)^\s*BGP neighbor is\s+([^,\s]+),\s*remote AS\s+(\d+),\s*"
            r"local AS\s+(\d+)",
            block,
        )
        if header is None:
            continue
        try:
            address = ip_address(header.group(1))
        except ValueError:
            continue
        local_as = int(header.group(3))
        state_match = re.search(
            r"(?im)^\s*BGP state\s*=\s*([^,\s]+)(?:,\s*up for\s+(.+))?\s*$",
            block,
        )
        family_match = re.search(r"(?im)^\s*For address family:\s*(.+?)\s*$", block)
        accepted_match = re.search(r"(?im)^\s*(\d+)\s+accepted prefixes\s*$", block)
        announced_match = re.search(r"(?im)^\s*(\d+)\s+announced prefixes\s*$", block)
        received_match = re.search(r"(?im)^\s*Received\s+(\d+)\s+messages", block)
        sent_match = re.search(r"(?im)^\s*Sent\s+(\d+)\s+messages", block)
        neighbors.append(
            BGPNeighbor(
                device_id=device_id,
                address=address,
                remote_as=int(header.group(2)),
                state=_state(state_match.group(1)) if state_match else BGPSessionState.UNKNOWN,
                uptime_seconds=(
                    parse_duration_seconds(state_match.group(2))
                    if state_match and state_match.group(2)
                    else None
                ),
                prefixes_received=(int(accepted_match.group(1)) if accepted_match else None),
                prefixes_advertised=(int(announced_match.group(1)) if announced_match else None),
                messages_received=(int(received_match.group(1)) if received_match else None),
                messages_sent=int(sent_match.group(1)) if sent_match else None,
                address_family=family_match.group(1).strip() if family_match else None,
            )
        )
    normalized, truncated = bounded_tuple(neighbors, MAX_ROUTING_NEIGHBORS)
    if not normalized:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS BGP neighbor rows were not recognized",
        )
    return BGPStatus(
        device_id=device_id,
        enabled=True,
        feature_state=FeatureState.ENABLED,
        parser=_metadata(
            variant,
            partial=any(item.state is BGPSessionState.UNKNOWN for item in normalized),
        ),
        local_as=local_as,
        neighbors=normalized,
        truncated=truncated,
    )


def _neighbor_blocks(output: str) -> tuple[str, ...]:
    matches = tuple(re.finditer(r"(?im)^\s*BGP neighbor is\s+", output))
    return tuple(
        output[match.start() : matches[index + 1].start() if index + 1 < len(matches) else None]
        for index, match in enumerate(matches)
    )


def _feature_absent(
    device_id: str,
    feature_state: FeatureState,
    variant: str,
) -> BGPStatus:
    return BGPStatus(
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


def _neighbors(device_id: str, output: str) -> tuple[BGPNeighbor, ...]:
    results = []
    in_table = False
    for line in output.splitlines():
        if re.match(r"(?i)^\s*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent", line):
            in_table = True
            continue
        if not in_table:
            continue
        if re.match(r"(?i)^\s*Total number of neighbors", line):
            break
        columns = line.split()
        if len(columns) < 10:
            continue
        try:
            address = ip_address(columns[0])
            remote_as = int(columns[2])
            received = int(columns[3])
            sent = int(columns[4])
        except ValueError:
            continue
        final = columns[-1]
        if final.isdigit():
            state = BGPSessionState.ESTABLISHED
            prefixes = int(final)
        else:
            state = _state(final)
            prefixes = None
        results.append(
            BGPNeighbor(
                device_id=device_id,
                address=address,
                remote_as=remote_as,
                state=state,
                uptime_seconds=parse_duration_seconds(columns[-2]),
                prefixes_received=prefixes,
                messages_received=received,
                messages_sent=sent,
            )
        )
    return tuple(results)


def _state(value: str) -> BGPSessionState:
    normalized = re.sub(r"[^a-z]", "", value.casefold())
    return {
        "established": BGPSessionState.ESTABLISHED,
        "idle": BGPSessionState.IDLE,
        "connect": BGPSessionState.CONNECT,
        "active": BGPSessionState.ACTIVE,
        "opensent": BGPSessionState.OPEN_SENT,
        "openconfirm": BGPSessionState.OPEN_CONFIRM,
    }.get(normalized, BGPSessionState.UNKNOWN)
