"""Small shared helpers for bounded FortiOS semantic parsers."""

import re
from collections.abc import Iterable
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address, ip_address

from netsage.drivers.fortios.parsers import FortiOSParseError

_PERMISSION_FAILURE = re.compile(
    r"(?i)(?:permission denied|insufficient permissions?|no permissions?|"
    r"not permitted|not authorized|no rights)"
)
_COMMAND_UNAVAILABLE = re.compile(
    r"(?i)(?:command fail|unknown action|command not found|parse error|"
    r"return code\s*-\d+|object does not exist|not supported on this platform)"
)


class FortiOSSemanticErrorCategory(StrEnum):
    EMPTY_OUTPUT = "empty_output"
    COMMAND_UNAVAILABLE = "command_unavailable"
    PERMISSION_DENIED = "permission_denied"
    OUTPUT_UNRECOGNIZED = "output_unrecognized"
    MALFORMED = "malformed"
    PARTIAL = "partial"


class FortiOSSemanticParseError(FortiOSParseError):
    """A categorized parser failure which never retains device output."""

    def __init__(self, category: FortiOSSemanticErrorCategory, message: str) -> None:
        super().__init__(message)
        self.category = category


def require_recognizable_output(output: str, domain: str) -> str:
    normalized = output.replace("\x00", "").strip()
    if not normalized:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.EMPTY_OUTPUT,
            f"FortiOS {domain} output was empty",
        )
    if _PERMISSION_FAILURE.search(normalized):
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.PERMISSION_DENIED,
            f"FortiOS {domain} permission was denied",
        )
    if _COMMAND_UNAVAILABLE.search(normalized):
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.COMMAND_UNAVAILABLE,
            f"FortiOS {domain} command was unavailable",
        )
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
    token = value.strip().strip("(),")
    if not token:
        return None
    bracketed = re.match(r"^\[([^]]+)](?::\d+)?$", token)
    candidates = (bracketed.group(1),) if bracketed else (token, token.rsplit(":", 1)[0])
    for candidate in candidates:
        try:
            return ip_address(candidate)
        except ValueError:
            continue
    return None
