"""Parse bounded FortiOS OSPF process and neighbor status."""

import re
from ipaddress import ip_address

from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.semantic.common import (
    bounded_tuple,
    parse_duration_seconds,
    require_recognizable_output,
)
from netsage.models import OSPFNeighbor, OSPFNeighborState, OSPFStatus
from netsage.models.observability import MAX_ROUTING_NEIGHBORS

_DISABLED = re.compile(r"(?i)ospf.*(?:not configured|disabled|not enabled)")


def parse_ospf_status(device_id: str, status_output: str, neighbors_output: str) -> OSPFStatus:
    combined = "\n".join((status_output, neighbors_output)).strip()
    if not combined:
        raise FortiOSParseError("FortiOS OSPF output was empty")
    if _DISABLED.search(combined):
        return OSPFStatus(device_id=device_id, enabled=False)
    status_text = require_recognizable_output(status_output, "OSPF status")
    neighbors_text = require_recognizable_output(neighbors_output, "OSPF neighbors")
    identity = re.search(
        r"(?im)^\s*Routing Process\s+[\"']?ospf\s+(\d+)[\"']?\s+with ID\s+([^\s]+)",
        status_text,
    ) or re.search(r"(?im)^\s*OSPF Router.*?ID\s*\(?([^\s)]+)\)?", status_text)
    has_neighbor_header = re.search(r"(?im)^\s*Neighbor ID\s+Pri\s+State", neighbors_text)
    if identity is None and has_neighbor_header is None:
        raise FortiOSParseError("FortiOS OSPF output was not recognized")
    process_match = re.search(r"(?im)^\s*OSPF process\s+(\d+)\s*:", neighbors_text)
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
        columns = line.split()
        if len(columns) < 6:
            continue
        try:
            neighbor_id = ip_address(columns[0])
            priority = int(columns[1])
            address = ip_address(columns[-2])
        except ValueError:
            continue
        state_text, separator, role = columns[2].partition("/")
        results.append(
            OSPFNeighbor(
                device_id=device_id,
                neighbor_id=neighbor_id,
                address=address,
                interface=columns[-1],
                state=_state(state_text),
                role=role or None if separator else None,
                priority=priority,
                dead_time_seconds=parse_duration_seconds(columns[3]),
            )
        )
    return tuple(results)


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
