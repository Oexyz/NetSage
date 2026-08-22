"""Parse FortiOS HA status into bounded vendor-neutral models."""

import re
from dataclasses import dataclass

from netsage.drivers.fortios.parsers import FortiOSParseError
from netsage.drivers.fortios.semantic.common import (
    bounded_tuple,
    parse_duration_seconds,
    require_recognizable_output,
)
from netsage.models import (
    HAMember,
    HARole,
    HAStatus,
    HASynchronizationState,
    HealthStatus,
)
from netsage.models.observability import MAX_HA_MEMBERS


@dataclass
class _MemberData:
    member_id: str
    hostname: str | None = None
    role: HARole = HARole.UNKNOWN
    synchronization: HASynchronizationState = HASynchronizationState.UNKNOWN
    cluster_index: int | None = None
    updated_seconds_ago: int | None = None
    sessions: int | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None


def parse_ha_status(device_id: str, output: str) -> HAStatus:
    text = require_recognizable_output(output, "HA status")
    values = _top_level_values(text)
    health_text = values.get("ha health status")
    mode = values.get("mode")
    if health_text is None and mode is None and "configuration status:" not in text.casefold():
        raise FortiOSParseError("FortiOS HA status output was not recognized")

    members: dict[str, _MemberData] = {}
    _parse_configuration_status(text, members)
    _parse_roles(text, members)
    _parse_usage(text, members)
    normalized_members, truncated = bounded_tuple(
        (_model(device_id, member) for member in members.values()),
        MAX_HA_MEMBERS,
    )
    primary = next(
        (member.member_id for member in normalized_members if member.role is HARole.PRIMARY),
        None,
    )
    normalized_mode = mode.casefold() if mode else ""
    enabled = None
    if normalized_mode:
        enabled = not any(word in normalized_mode for word in ("standalone", "disabled", "none"))
    elif normalized_members:
        enabled = True
    return HAStatus(
        device_id=device_id,
        enabled=enabled,
        mode=mode,
        group_name=values.get("group name"),
        group_id=_integer(values.get("group id") or values.get("group")),
        health=_health(health_text),
        cluster_uptime_seconds=parse_duration_seconds(values.get("cluster uptime")),
        primary_member_id=primary,
        members=normalized_members,
        truncated=truncated,
    )


def _top_level_values(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if line[:1].isspace():
            continue
        key, separator, value = line.partition(":")
        if separator:
            values[key.strip().casefold()] = value.strip()
    return values


def _parse_configuration_status(output: str, members: dict[str, _MemberData]) -> None:
    pattern = re.compile(
        r"(?im)^\s*(?P<id>[^\s:(]+)\s*\(updated\s+(?P<age>\d+)\s+seconds?\s+ago\)"
        r"\s*:\s*(?P<state>in[- ]sync|out[- ]of[- ]sync|not[- ]synchronized)\s*$"
    )
    for match in pattern.finditer(output):
        member = members.setdefault(match.group("id"), _MemberData(match.group("id")))
        member.updated_seconds_ago = int(match.group("age"))
        state = match.group("state").casefold().replace(" ", "-")
        member.synchronization = (
            HASynchronizationState.IN_SYNC
            if state == "in-sync"
            else HASynchronizationState.OUT_OF_SYNC
        )


def _parse_roles(output: str, members: dict[str, _MemberData]) -> None:
    detailed = re.compile(
        r"(?im)^\s*(?P<role>primary|secondary|master|slave)\s*:\s*"
        r"(?P<hostname>[^,]+?)\s*,\s*(?P<id>[^,\s]+)\s*,\s*HA\s+"
        r"(?:cluster|operating)\s+index\s*=\s*(?P<index>\d+)\s*$"
    )
    compact = re.compile(
        r"(?im)^\s*(?P<role>primary|secondary|master|slave)\s*:\s*"
        r"(?P<id>[^,\s]+)\s*,\s*HA\s+(?:cluster|operating)\s+index\s*=\s*"
        r"(?P<index>\d+)\s*$"
    )
    for match in detailed.finditer(output):
        member = members.setdefault(match.group("id"), _MemberData(match.group("id")))
        member.hostname = match.group("hostname").strip()
        member.role = _role(match.group("role"))
        member.cluster_index = int(match.group("index"))
    for match in compact.finditer(output):
        member = members.setdefault(match.group("id"), _MemberData(match.group("id")))
        member.role = _role(match.group("role"))
        member.cluster_index = int(match.group("index"))


def _parse_usage(output: str, members: dict[str, _MemberData]) -> None:
    lines = output.splitlines()
    header = re.compile(r"^\s*([^\s:(]+)\s*\(updated\s+(\d+)\s+seconds?\s+ago\):\s*$")
    usage = re.compile(
        r"sessions=(\d+).*?average-cpu-user/nice/system/idle="
        r"(\d+)%/(\d+)%/(\d+)%/(\d+)%.*?memory=(\d+)%",
        re.IGNORECASE,
    )
    for index, line in enumerate(lines[:-1]):
        match = header.match(line)
        if match is None:
            continue
        usage_match = usage.search(lines[index + 1])
        if usage_match is None:
            continue
        member_id = match.group(1)
        member = members.setdefault(member_id, _MemberData(member_id))
        member.updated_seconds_ago = int(match.group(2))
        member.sessions = int(usage_match.group(1))
        member.cpu_percent = 100.0 - float(usage_match.group(5))
        member.memory_percent = float(usage_match.group(6))


def _model(device_id: str, value: _MemberData) -> HAMember:
    return HAMember(
        device_id=device_id,
        member_id=value.member_id,
        hostname=value.hostname,
        role=value.role,
        synchronization=value.synchronization,
        cluster_index=value.cluster_index,
        updated_seconds_ago=value.updated_seconds_ago,
        sessions=value.sessions,
        cpu_percent=value.cpu_percent,
        memory_percent=value.memory_percent,
    )


def _role(value: str) -> HARole:
    return HARole.PRIMARY if value.casefold() in {"primary", "master"} else HARole.SECONDARY


def _health(value: str | None) -> HealthStatus:
    if value is None:
        return HealthStatus.UNKNOWN
    normalized = value.casefold()
    if normalized.strip() in {"ok", "healthy", "good"}:
        return HealthStatus.HEALTHY
    if any(word in normalized for word in ("critical", "failed", "error", "unhealthy")):
        return HealthStatus.UNHEALTHY
    if any(word in normalized for word in ("warning", "degraded", "down")):
        return HealthStatus.DEGRADED
    return HealthStatus.UNKNOWN


def _integer(value: str | None) -> int | None:
    if value is None:
        return None
    match = re.search(r"\d+", value)
    return int(match.group()) if match else None
