"""Small shared helpers for bounded FortiOS semantic parsers."""

import re
from collections.abc import Iterable
from ipaddress import IPv4Address, IPv6Address, ip_address

from netsage.drivers.fortios.parsers import FortiOSParseError

_COMMAND_FAILURE = re.compile(
    r"(?i)(?:command fail|unknown action|parse error|return code\s*-\d+|"
    r"object does not exist|not supported on this platform)"
)


def require_recognizable_output(output: str, domain: str) -> str:
    normalized = output.replace("\x00", "").strip()
    if not normalized:
        raise FortiOSParseError(f"FortiOS {domain} output was empty")
    if _COMMAND_FAILURE.search(normalized):
        raise FortiOSParseError(f"FortiOS {domain} command was unsupported")
    return normalized


def bounded_tuple[ItemT](items: Iterable[ItemT], limit: int) -> tuple[tuple[ItemT, ...], bool]:
    values = tuple(items)
    return values[:limit], len(values) > limit


def parse_duration_seconds(value: str | None) -> int | None:
    if value is None:
        return None
    text = value.strip().casefold().replace(",", " ")
    if not text:
        return None
    if re.fullmatch(r"\d+(?::\d+){1,2}", text):
        parts = [int(part) for part in text.split(":")]
        if len(parts) == 2:
            return parts[0] * 60 + parts[1]
        return parts[0] * 3600 + parts[1] * 60 + parts[2]
    total = 0
    found = False
    units = {
        "d": 86400,
        "day": 86400,
        "days": 86400,
        "h": 3600,
        "hour": 3600,
        "hours": 3600,
        "m": 60,
        "min": 60,
        "mins": 60,
        "minute": 60,
        "minutes": 60,
        "s": 1,
        "sec": 1,
        "secs": 1,
        "second": 1,
        "seconds": 1,
    }
    for amount, unit in re.findall(r"(\d+)\s*([a-z]+)", text):
        multiplier = units.get(unit)
        if multiplier is not None:
            total += int(amount) * multiplier
            found = True
    clock_match = re.search(r"(?<!\d)(\d+):(\d+):(\d+)(?!\d)", text)
    if clock_match:
        total += (
            int(clock_match.group(1)) * 3600
            + int(clock_match.group(2)) * 60
            + int(clock_match.group(3))
        )
        found = True
    return total if found else None


def endpoint_address(value: str) -> IPv4Address | IPv6Address | None:
    token = value.strip().strip("[](),")
    if not token:
        return None
    candidates = (token, token.rsplit(":", 1)[0])
    for candidate in candidates:
        try:
            return ip_address(candidate)
        except ValueError:
            continue
    return None
