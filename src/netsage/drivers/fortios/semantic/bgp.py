"""Parse bounded FortiOS BGP summary output."""

import re
from ipaddress import ip_address

from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.semantic.common import (
    bounded_tuple,
    parse_duration_seconds,
    require_recognizable_output,
)
from netsage.models import BGPNeighbor, BGPSessionState, BGPStatus
from netsage.models.observability import MAX_ROUTING_NEIGHBORS

_DISABLED = re.compile(r"(?i)bgp.*(?:not configured|disabled|not enabled)")


def parse_bgp_status(device_id: str, output: str) -> BGPStatus:
    text = require_recognizable_output(output, "BGP summary")
    if _DISABLED.search(text):
        return BGPStatus(device_id=device_id, enabled=False)
    identity = re.search(
        r"(?im)^\s*BGP router identifier\s+([^,\s]+),\s*local AS number\s+(\d+)",
        text,
    )
    table = re.search(r"(?im)^\s*BGP table version is\s+(\d+)", text)
    has_header = re.search(r"(?im)^\s*Neighbor\s+V\s+AS\s+MsgRcvd\s+MsgSent", text)
    if identity is None and has_header is None:
        raise FortiOSParseError("FortiOS BGP summary output was not recognized")
    neighbors, truncated = bounded_tuple(_neighbors(device_id, text), MAX_ROUTING_NEIGHBORS)
    try:
        router_id = ip_address(identity.group(1)) if identity else None
    except ValueError:
        router_id = None
    return BGPStatus(
        device_id=device_id,
        enabled=True,
        router_id=router_id,
        local_as=int(identity.group(2)) if identity else None,
        table_version=int(table.group(1)) if table else None,
        neighbors=neighbors,
        truncated=truncated,
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
