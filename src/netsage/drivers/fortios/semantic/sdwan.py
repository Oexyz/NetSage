"""Parse bounded FortiOS SD-WAN member and health-check observations."""

import re
from ipaddress import ip_address

from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.semantic.common import (
    bounded_tuple,
    require_recognizable_output,
)
from netsage.models import (
    SDWANHealthCheck,
    SDWANMember,
    SDWANPathState,
    SDWANSLAState,
    SDWANStatus,
)
from netsage.models.observability import (
    MAX_SDWAN_HEALTH_CHECKS,
    MAX_SDWAN_MEMBERS,
)

_DISABLED = re.compile(
    r"(?i)(?:sd-wan|virtual[ -]wan[ -]link).*"
    r"(?:not configured|disabled|not enabled|not running)"
)


def parse_sdwan_status(device_id: str, members_output: str, health_output: str) -> SDWANStatus:
    combined = "\n".join((members_output, health_output)).strip()
    if not combined:
        raise FortiOSParseError("FortiOS SD-WAN output was empty")
    if _DISABLED.search(combined):
        return SDWANStatus(device_id=device_id, enabled=False)
    members_text = require_recognizable_output(members_output, "SD-WAN members")
    health_text = require_recognizable_output(health_output, "SD-WAN health-check")
    members, members_truncated = bounded_tuple(_members(device_id, members_text), MAX_SDWAN_MEMBERS)
    health_checks, health_truncated = bounded_tuple(
        _health_checks(device_id, health_text), MAX_SDWAN_HEALTH_CHECKS
    )
    if not members and not health_checks:
        raise FortiOSParseError("FortiOS SD-WAN output was not recognized")
    return SDWANStatus(
        device_id=device_id,
        enabled=True,
        members=members,
        health_checks=health_checks,
        truncated=members_truncated or health_truncated,
    )


def _members(device_id: str, output: str) -> tuple[SDWANMember, ...]:
    pattern = re.compile(r"(?im)^\s*Member\((?P<seq>\d+)\)\s*:\s*(?P<body>.+)$")
    results = []
    for match in pattern.finditer(output):
        body = match.group("body")
        interface = _text_field(body, "interface")
        gateway_text = _text_field(body, "gateway")
        try:
            gateway = ip_address(gateway_text) if gateway_text else None
        except ValueError:
            gateway = None
        results.append(
            SDWANMember(
                device_id=device_id,
                sequence=int(match.group("seq")),
                interface=interface,
                gateway=gateway,
                priority=_integer_field(body, "priority"),
                weight=_integer_field(body, "weight"),
            )
        )
    return tuple(results)


def _health_checks(device_id: str, output: str) -> tuple[SDWANHealthCheck, ...]:
    results = []
    current_name: str | None = None
    header = re.compile(r"(?i)^\s*Health\s+Check\((.+)\)\s*:\s*$")
    sequence = re.compile(
        r"(?i)^\s*Seq\((?P<seq>\d+)(?:\s+(?P<interface>[^)]+))?\)\s*:\s*(?P<body>.+)$"
    )
    for line in output.splitlines():
        header_match = header.match(line)
        if header_match:
            current_name = header_match.group(1).strip()
            continue
        sequence_match = sequence.match(line)
        if sequence_match is None or current_name is None:
            continue
        body = sequence_match.group("body")
        state_match = re.search(r"(?i)\bstate\(([^)]+)\)", body)
        state = _path_state(state_match.group(1) if state_match else None)
        sla_state = _sla_state(body)
        sla_map_match = re.search(r"(?i)\bsla_map\s*=\s*(0x[0-9a-f]+|\d+)", body)
        results.append(
            SDWANHealthCheck(
                device_id=device_id,
                name=current_name,
                member_sequence=int(sequence_match.group("seq")),
                interface=(sequence_match.group("interface") or "").strip() or None,
                state=state,
                packet_loss_percent=_float_metric(body, "packet-loss"),
                latency_ms=_float_metric(body, "latency"),
                jitter_ms=_float_metric(body, "jitter"),
                sla_state=sla_state,
                sla_map=(int(sla_map_match.group(1), 0) if sla_map_match else None),
            )
        )
    return tuple(results)


def _text_field(body: str, name: str) -> str | None:
    match = re.search(rf"(?i)\b{re.escape(name)}\s*:\s*([^,]+)", body)
    return match.group(1).strip() if match else None


def _integer_field(body: str, name: str) -> int | None:
    value = _text_field(body, name)
    if value is None:
        return None
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None


def _float_metric(body: str, name: str) -> float | None:
    match = re.search(rf"(?i)\b{re.escape(name)}\s*\(?\s*([\d.]+)%?\s*\)?", body)
    return float(match.group(1)) if match else None


def _path_state(value: str | None) -> SDWANPathState:
    if value is None:
        return SDWANPathState.UNKNOWN
    normalized = value.casefold().strip()
    if normalized in {"alive", "up", "healthy"}:
        return SDWANPathState.ALIVE
    if normalized in {"dead", "down", "failed"}:
        return SDWANPathState.DEAD
    if normalized in {"degraded", "warning"}:
        return SDWANPathState.DEGRADED
    return SDWANPathState.UNKNOWN


def _sla_state(body: str) -> SDWANSLAState:
    match = re.search(
        r"(?i)\b(?:sla(?:-state)?\((pass(?:ing)?|fail(?:ing)?)\)|"
        r"sla-state\s*[=:]\s*(pass(?:ing)?|fail(?:ing)?))",
        body,
    )
    if match is None:
        return SDWANSLAState.UNKNOWN
    value = next(group for group in match.groups() if group is not None).casefold()
    return SDWANSLAState.PASSING if value.startswith("pass") else SDWANSLAState.FAILING
