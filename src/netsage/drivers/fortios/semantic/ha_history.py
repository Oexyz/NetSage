"""Parse bounded FortiOS HA history into normalized, identity-safe events."""

import re
from datetime import datetime

from netsage.drivers.fortios.semantic.common import require_recognizable_output
from netsage.models import (
    HAEvent,
    HAEventState,
    HAEventType,
    HAHistory,
    HARole,
    HATimelineOrdering,
    HATimestampKind,
    SemanticParserMetadata,
    SemanticParserState,
)
from netsage.models.ha_diagnostics import MAX_HA_HISTORY_EVENTS

MAX_HA_HISTORY_SOURCE_CHARACTERS = 1_000_000

_TIMESTAMP_PREFIX = re.compile(
    r"^\s*[^0-9\r\n]{0,3}"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)"
    r"[^A-Za-z0-9\r\n]{0,3}\s*(?P<message>.*)$"
)
_MEMBER_HEARTBEAT_LOST = re.compile(
    r"(?i)\bmember\s+(?P<member>[^\s,;]+)\s+lost\s+heartbeat"
    r"(?:\s+on\s+hbdev\s+(?P<interface>[^\s,;]+))?"
)
_HEARTBEAT_SOURCE_LOST = re.compile(
    r"(?i)\bheartbeat\b.*?\bfrom\s+(?P<member>[^\s,;]+)\s+lost\b"
    r"(?:.*?\bhbdev(?:\s+(?P<interface>[^\s,;]+))?)?"
)
_HEARTBEAT_RESTORED = re.compile(
    r"(?i)\bheartbeat\b.*?\b(restored|recovered|received again|found)\b"
)
_NEW_MEMBER = re.compile(
    r"(?i)\bnew\s+member\s+(?P<member>[^\s,;]+)\s+"
    r"(?:joins?|joined|entered|added\s+to)\s+(?:the\s+)?cluster\b"
)
_MEMBER_LEFT = re.compile(
    r"(?i)\bmember\s+(?P<member>[^\s,;]+)\s+"
    r"(?:left|leaves|departed|removed\s+from)\s+(?:the\s+)?cluster\b"
)
_MEMBER_RESTART = re.compile(r"(?i)\bmember\s+(?P<member>[^\s,;]+).*?\b(rebooted|restarted)\b")
_MEMBER_BOOT = re.compile(r"(?i)\bmember\s+(?P<member>[^\s,;]+).*?\bbooted\b")
_HA_PROCESS_RESTART = re.compile(
    r"(?i)\b(?:ha|hasync|hatalk)\s+(?:daemon|process)\b.*?\b(restarted|restart)\b"
)
_PRIMARY_CHANGED = re.compile(
    r"(?i)\b(?P<member>[^\s,;]+)\s+is\s+"
    r"(?:elected|selected|chosen|configured)\s+as\s+the\s+cluster\s+"
    r"(?:primary|master)\b"
)
_FAILOVER = re.compile(r"(?i)\b(failover|primary\s+changed|role\s+changed)\b")
_SYNC_LOST = re.compile(r"(?i)\b(out[- ]of[- ]sync|not[- ]synchronized|sync\s+lost)\b")
_SYNC_RESTORED = re.compile(r"(?i)\b(in[- ]sync|sync\s+restored|synchronized\s+again)\b")
_LINK_CHANGE = re.compile(r"(?i)\blink\s+status\s+changed\b")
_HBDEV = re.compile(r"(?i)\bhbdev\s+(?P<interface>[^\s,;]+)")
_TOKEN_BEFORE_LINK = re.compile(r"(?i)(?P<interface>[^\s,;]+)\s+link\s+status\s+changed\b")
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")


def parse_ha_history(
    device_id: str,
    output: str,
    *,
    variant: str = "ha-history-v1",
) -> HAHistory:
    source = require_recognizable_output(output, "HA history")
    source_truncated = len(source) > MAX_HA_HISTORY_SOURCE_CHARACTERS
    text = source[:MAX_HA_HISTORY_SOURCE_CHARACTERS]
    if source_truncated and "\n" in text:
        text = text.rsplit("\n", 1)[0]

    lines = tuple(line for line in text.splitlines() if line.strip())
    member_aliases: dict[str, str] = {}
    unstable_members: set[str] = set()
    events: list[HAEvent] = []
    seen: set[tuple[object, ...]] = set()
    duplicates = 0

    for source_index, line in enumerate(lines):
        timestamp, timestamp_kind, message = _timestamp_and_message(line)
        event = _event(
            device_id=device_id,
            source_index=source_index,
            timestamp=timestamp,
            timestamp_kind=timestamp_kind,
            message=message,
            member_aliases=member_aliases,
            unstable_members=unstable_members,
        )
        key = _deduplication_key(event)
        if event.event_type is not HAEventType.UNKNOWN and key in seen:
            duplicates += 1
            continue
        seen.add(key)
        events.append(event)

    event_truncated = len(events) > MAX_HA_HISTORY_EVENTS
    bounded = tuple(events[:MAX_HA_HISTORY_EVENTS])
    truncated = source_truncated or event_truncated
    unrecognized = sum(event.event_type is HAEventType.UNKNOWN for event in bounded)
    timestamped = sum(event.timestamp is not None for event in bounded)
    ordering = (
        HATimelineOrdering.TIMESTAMP
        if bounded and timestamped == len(bounded)
        else HATimelineOrdering.UNCERTAIN
    )
    state = SemanticParserState.PARTIAL if truncated or unrecognized else SemanticParserState.PARSED
    return HAHistory(
        device_id=device_id,
        parser=SemanticParserMetadata(
            state=state,
            variant=variant,
            attempted_variants=(variant,),
        ),
        events=bounded,
        ordering=ordering,
        source_line_count=len(lines),
        unrecognized_event_count=unrecognized,
        duplicate_event_count=duplicates,
        truncated=truncated,
    )


def _timestamp_and_message(
    line: str,
) -> tuple[datetime | None, HATimestampKind, str]:
    match = _TIMESTAMP_PREFIX.match(line)
    if match is None:
        return None, HATimestampKind.UNKNOWN, line.strip()
    raw = match.group("timestamp")
    normalized = raw.replace(" ", "T", 1)
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    if re.search(r"[+-]\d{4}$", normalized):
        normalized = f"{normalized[:-5]}{normalized[-5:-2]}:{normalized[-2:]}"
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError:
        return None, HATimestampKind.UNKNOWN, line.strip()
    aware = timestamp.tzinfo is not None and timestamp.utcoffset() is not None
    return (
        timestamp,
        HATimestampKind.OFFSET_AWARE if aware else HATimestampKind.DEVICE_LOCAL,
        match.group("message").strip(),
    )


def _event(
    *,
    device_id: str,
    source_index: int,
    timestamp: datetime | None,
    timestamp_kind: HATimestampKind,
    message: str,
    member_aliases: dict[str, str],
    unstable_members: set[str],
) -> HAEvent:
    def make(
        event_type: HAEventType,
        *,
        member_ref: str | None = None,
        role: HARole = HARole.UNKNOWN,
        heartbeat_interface: str | None = None,
        previous_state: HAEventState = HAEventState.UNKNOWN,
        new_state: HAEventState = HAEventState.UNKNOWN,
    ) -> HAEvent:
        return HAEvent(
            device_id=device_id,
            source_index=source_index,
            timestamp=timestamp,
            timestamp_kind=timestamp_kind,
            event_type=event_type,
            member_ref=member_ref,
            role=role,
            heartbeat_interface=heartbeat_interface,
            previous_state=previous_state,
            new_state=new_state,
        )

    process = _HA_PROCESS_RESTART.search(message)
    if process:
        return make(HAEventType.HA_PROCESS_RESTARTED)

    member_restart = _MEMBER_RESTART.search(message)
    if member_restart:
        member_ref = _member_ref(member_restart.group("member"), member_aliases)
        return make(
            HAEventType.MEMBER_RESTARTED,
            member_ref=member_ref,
        )
    member_boot = _MEMBER_BOOT.search(message)
    if member_boot:
        member_ref = _member_ref(member_boot.group("member"), member_aliases)
        return make(
            HAEventType.MEMBER_BOOTED,
            member_ref=member_ref,
        )

    link_change = _LINK_CHANGE.search(message)
    if link_change:
        previous_state, new_state = _link_states(message[link_change.end() :])
        interface = _heartbeat_interface(message)
        event_type = HAEventType.HEARTBEAT_INTERFACE_STATE_CHANGED
        if new_state is HAEventState.DOWN:
            event_type = HAEventType.HEARTBEAT_INTERFACE_DOWN
        elif new_state is HAEventState.UP:
            event_type = HAEventType.HEARTBEAT_INTERFACE_RESTORED
        return make(
            event_type,
            heartbeat_interface=interface,
            previous_state=previous_state,
            new_state=new_state,
        )

    heartbeat_lost = _MEMBER_HEARTBEAT_LOST.search(message)
    if heartbeat_lost:
        member_ref = _member_ref(heartbeat_lost.group("member"), member_aliases)
        if member_ref is not None:
            unstable_members.add(member_ref)
        return make(
            HAEventType.HEARTBEAT_LOST,
            member_ref=member_ref,
            heartbeat_interface=_safe_token(heartbeat_lost.group("interface")),
            previous_state=HAEventState.UP,
            new_state=HAEventState.DOWN,
        )
    source_lost = _HEARTBEAT_SOURCE_LOST.search(message)
    if source_lost:
        member_ref = _member_ref(source_lost.group("member"), member_aliases)
        if member_ref is not None:
            unstable_members.add(member_ref)
        return make(
            HAEventType.HEARTBEAT_LOST,
            member_ref=member_ref,
            heartbeat_interface=_safe_token(source_lost.group("interface")),
            previous_state=HAEventState.UP,
            new_state=HAEventState.DOWN,
        )
    if _HEARTBEAT_RESTORED.search(message):
        return make(
            HAEventType.HEARTBEAT_RESTORED,
            previous_state=HAEventState.DOWN,
            new_state=HAEventState.UP,
        )

    new_member = _NEW_MEMBER.search(message)
    if new_member:
        member_ref = _member_ref(new_member.group("member"), member_aliases)
        rejoined = member_ref is not None and member_ref in unstable_members
        if rejoined:
            unstable_members.discard(member_ref)
        return make(
            HAEventType.MEMBER_REJOINED if rejoined else HAEventType.MEMBER_JOINED,
            member_ref=member_ref,
        )
    member_left = _MEMBER_LEFT.search(message)
    if member_left:
        member_ref = _member_ref(member_left.group("member"), member_aliases)
        if member_ref is not None:
            unstable_members.add(member_ref)
        return make(
            HAEventType.MEMBER_LEFT,
            member_ref=member_ref,
        )

    primary = _PRIMARY_CHANGED.search(message)
    if primary:
        return make(
            HAEventType.PRIMARY_CHANGED,
            member_ref=_member_ref(primary.group("member"), member_aliases),
            role=HARole.PRIMARY,
        )
    if _FAILOVER.search(message):
        return make(HAEventType.FAILOVER)
    if _SYNC_LOST.search(message):
        return make(
            HAEventType.SYNC_LOST,
            previous_state=HAEventState.IN_SYNC,
            new_state=HAEventState.OUT_OF_SYNC,
        )
    if _SYNC_RESTORED.search(message):
        return make(
            HAEventType.SYNC_RESTORED,
            previous_state=HAEventState.OUT_OF_SYNC,
            new_state=HAEventState.IN_SYNC,
        )
    return make(HAEventType.UNKNOWN)


def _heartbeat_interface(message: str) -> str | None:
    hbdev = _HBDEV.search(message)
    if hbdev:
        return _safe_token(hbdev.group("interface"))
    preceding = _TOKEN_BEFORE_LINK.search(message)
    return _safe_token(preceding.group("interface")) if preceding else None


def _link_states(tail: str) -> tuple[HAEventState, HAEventState]:
    values = tuple(int(item) for item in re.findall(r"\d+", tail))
    if len(values) < 2:
        return HAEventState.UNKNOWN, HAEventState.UNKNOWN
    return _binary_link_state(values[-2]), _binary_link_state(values[-1])


def _binary_link_state(value: int) -> HAEventState:
    if value == 1:
        return HAEventState.UP
    if value == 0:
        return HAEventState.DOWN
    return HAEventState.UNKNOWN


def _member_ref(raw: str | None, aliases: dict[str, str]) -> str | None:
    token = _safe_token(raw)
    if token is None:
        return None
    key = token.casefold()
    if key not in aliases:
        aliases[key] = f"member-{len(aliases) + 1}"
    return aliases[key]


def _safe_token(raw: str | None) -> str | None:
    if raw is None:
        return None
    token = raw.strip().strip("[]()<>\"'")
    return token if _SAFE_TOKEN.fullmatch(token) else None


def _deduplication_key(event: HAEvent) -> tuple[object, ...]:
    return (
        event.timestamp,
        event.event_type,
        event.member_ref,
        event.role,
        event.heartbeat_interface.casefold() if event.heartbeat_interface else None,
        event.previous_state,
        event.new_state,
    )
