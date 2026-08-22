"""Deterministic temporal correlation for typed HA diagnostic evidence."""

from collections.abc import Sequence
from datetime import datetime

from netsage.models import (
    HAChecksumStatus,
    HACorrelationResult,
    HAEvent,
    HAEventType,
    HAFaultDomain,
    HAHistory,
    HAIncidentEpisode,
    HAObservedPattern,
    HAStatus,
    HASynchronizationState,
    HATimeline,
    Interface,
    InterfaceState,
)

HA_CORRELATION_WINDOW_SECONDS = 300

_INCIDENT_TYPES = frozenset(
    {
        HAEventType.HEARTBEAT_LOST,
        HAEventType.HEARTBEAT_RESTORED,
        HAEventType.HEARTBEAT_INTERFACE_DOWN,
        HAEventType.HEARTBEAT_INTERFACE_RESTORED,
        HAEventType.MEMBER_LEFT,
        HAEventType.MEMBER_JOINED,
        HAEventType.MEMBER_REJOINED,
        HAEventType.FAILOVER,
        HAEventType.MEMBER_RESTARTED,
        HAEventType.MEMBER_BOOTED,
        HAEventType.HA_PROCESS_RESTARTED,
        HAEventType.SYNC_LOST,
        HAEventType.SYNC_RESTORED,
    }
)
_MEMBERSHIP_TYPES = frozenset(
    {HAEventType.MEMBER_LEFT, HAEventType.MEMBER_JOINED, HAEventType.MEMBER_REJOINED}
)
_RESTART_TYPES = frozenset({HAEventType.MEMBER_RESTARTED, HAEventType.MEMBER_BOOTED})


def correlate_ha_diagnostics(
    *,
    history: HAHistory,
    status: HAStatus,
    checksum: HAChecksumStatus | None,
    interfaces: Sequence[Interface] = (),
    window_seconds: int = HA_CORRELATION_WINDOW_SECONDS,
) -> HACorrelationResult:
    if window_seconds < 1 or window_seconds > 3_600:
        raise ValueError("HA correlation window must be between 1 and 3600 seconds")
    if history.device_id != status.device_id:
        raise ValueError("HA correlation device identity mismatch")
    if checksum is not None and checksum.device_id != status.device_id:
        raise ValueError("HA checksum device identity mismatch")
    if any(interface.device_id != status.device_id for interface in interfaces):
        raise ValueError("HA interface device identity mismatch")

    timeline = HATimeline(
        events=history.events,
        ordering=history.ordering,
        duplicates_removed=history.duplicate_event_count,
        truncated=history.truncated,
    )
    episodes = _episodes(history.events, window_seconds)
    event_types = {event.event_type for event in history.events}
    patterns: set[HAObservedPattern] = set()
    fault_domains: set[HAFaultDomain] = set()

    out_of_sync = any(
        member.synchronization is HASynchronizationState.OUT_OF_SYNC for member in status.members
    )
    checksum_mismatch = checksum is not None and checksum.mismatch_count > 0
    if out_of_sync or checksum_mismatch:
        patterns.add(HAObservedPattern.CONFIGURATION_DRIFT)
        fault_domains.add(HAFaultDomain.CONFIGURATION_SYNCHRONIZATION)

    heartbeat_lost = HAEventType.HEARTBEAT_LOST in event_types
    membership = bool(event_types.intersection(_MEMBERSHIP_TYPES))
    unstable_episodes = tuple(
        episode
        for episode in episodes
        if HAEventType.HEARTBEAT_LOST in episode.event_types
        or bool(set(episode.event_types).intersection(_MEMBERSHIP_TYPES))
    )
    communication = heartbeat_lost and (
        membership
        or HAEventType.HEARTBEAT_RESTORED in event_types
        or sum(event.event_type is HAEventType.HEARTBEAT_LOST for event in history.events) > 1
    )
    if communication:
        patterns.add(HAObservedPattern.HEARTBEAT_COMMUNICATION_INSTABILITY)
        fault_domains.add(HAFaultDomain.HA_HEARTBEAT_COMMUNICATION)
    if membership:
        patterns.add(HAObservedPattern.CLUSTER_MEMBERSHIP_INSTABILITY)
        fault_domains.add(HAFaultDomain.CLUSTER_MEMBERSHIP)
    if len(unstable_episodes) > 1:
        patterns.add(HAObservedPattern.REPEATED_INSTABILITY)

    heartbeat_interfaces = tuple(
        sorted(
            {
                event.heartbeat_interface
                for event in history.events
                if event.heartbeat_interface is not None
            },
            key=str.casefold,
        )
    )
    interface_map = {interface.name.casefold(): interface for interface in interfaces}
    matched_interfaces = tuple(
        interface_map[name.casefold()]
        for name in heartbeat_interfaces
        if name.casefold() in interface_map
    )
    historical_interface_flap = _has_interface_flap(history.events)
    interface_unavailable = any(
        interface.admin_state is InterfaceState.DOWN
        or interface.operational_state is InterfaceState.DOWN
        for interface in matched_interfaces
    )
    interface_error_signal = any(_has_error_signal(interface) for interface in matched_interfaces)
    if interface_unavailable:
        patterns.add(HAObservedPattern.HEARTBEAT_INTERFACE_UNAVAILABLE)
        fault_domains.add(HAFaultDomain.HA_HEARTBEAT_INTERFACE)
    if (historical_interface_flap and matched_interfaces) or (
        communication and interface_error_signal
    ):
        patterns.add(HAObservedPattern.HEARTBEAT_INTERFACE_INSTABILITY)
        fault_domains.add(HAFaultDomain.HA_HEARTBEAT_INTERFACE)

    if event_types.intersection(_RESTART_TYPES):
        patterns.add(HAObservedPattern.MEMBER_RESTART)
        fault_domains.add(HAFaultDomain.MEMBER_RESTART)
    if HAEventType.HA_PROCESS_RESTARTED in event_types:
        patterns.add(HAObservedPattern.HA_PROCESS_RESTART)
        fault_domains.add(HAFaultDomain.HA_PROCESS)

    missing: list[str] = []
    if history.truncated:
        missing.append("ha_history_truncated")
    recognized = len(history.events) - history.unrecognized_event_count
    if history.unrecognized_event_count and recognized == 0:
        missing.append("ha_history_unrecognized")
    if checksum is None:
        missing.append("checksum_detail_unavailable")
    if communication or membership:
        if not matched_interfaces:
            missing.append("heartbeat_interface_state_unavailable")
        if not event_types.intersection(_RESTART_TYPES):
            missing.append("member_restart_evidence_unavailable")
        missing.append("heartbeat_physical_layer_unobservable")

    ordered_patterns = tuple(sorted(patterns, key=lambda item: item.value))
    ordered_domains = tuple(sorted(fault_domains, key=lambda item: item.value))
    if not ordered_domains:
        ordered_domains = (HAFaultDomain.UNKNOWN,)
    return HACorrelationResult(
        timeline=timeline,
        episodes=episodes,
        observed_patterns=ordered_patterns,
        fault_domains=ordered_domains,
        heartbeat_interfaces=heartbeat_interfaces,
        matched_interface_count=len(matched_interfaces),
        missing_evidence=tuple(dict.fromkeys(missing)),
        specific_physical_cause_confirmed=False,
    )


def _episodes(
    events: Sequence[HAEvent],
    window_seconds: int,
) -> tuple[HAIncidentEpisode, ...]:
    significant = tuple(event for event in events if event.event_type in _INCIDENT_TYPES)
    timestamped = tuple(event for event in significant if event.timestamp is not None)
    if not timestamped:
        return ()
    ordered = tuple(sorted(timestamped, key=_timestamp_sort_key))
    groups: list[list[HAEvent]] = []
    for event in ordered:
        if not groups:
            groups.append([event])
            continue
        gap = _time_gap(groups[-1][-1].timestamp, event.timestamp)
        if gap is None or gap > window_seconds:
            groups.append([event])
        else:
            groups[-1].append(event)
    return tuple(_episode(index, group) for index, group in enumerate(groups, start=1))


def _timestamp_sort_key(event: HAEvent) -> tuple[int, str, int]:
    timestamp = event.timestamp
    if timestamp is None:
        return (1, "", event.source_index)
    return (0, timestamp.isoformat(), event.source_index)


def _time_gap(previous: datetime | None, current: datetime | None) -> float | None:
    if previous is None or current is None:
        return None
    previous_aware = previous.tzinfo is not None and previous.utcoffset() is not None
    current_aware = current.tzinfo is not None and current.utcoffset() is not None
    if previous_aware != current_aware:
        return None
    return max(0.0, (current - previous).total_seconds())


def _episode(index: int, events: Sequence[HAEvent]) -> HAIncidentEpisode:
    timestamps = tuple(event.timestamp for event in events if event.timestamp is not None)
    return HAIncidentEpisode(
        episode_index=index,
        event_indices=tuple(event.source_index for event in events),
        started_at=timestamps[0] if timestamps else None,
        ended_at=timestamps[-1] if timestamps else None,
        event_types=tuple(dict.fromkeys(event.event_type for event in events)),
        member_refs=tuple(
            sorted({event.member_ref for event in events if event.member_ref is not None})
        ),
        heartbeat_interfaces=tuple(
            sorted(
                {
                    event.heartbeat_interface
                    for event in events
                    if event.heartbeat_interface is not None
                },
                key=str.casefold,
            )
        ),
    )


def _has_interface_flap(events: Sequence[HAEvent]) -> bool:
    states: dict[str, set[HAEventType]] = {}
    for event in events:
        if event.heartbeat_interface is None:
            continue
        states.setdefault(event.heartbeat_interface.casefold(), set()).add(event.event_type)
    return any(
        HAEventType.HEARTBEAT_INTERFACE_DOWN in values
        and HAEventType.HEARTBEAT_INTERFACE_RESTORED in values
        for values in states.values()
    )


def _has_error_signal(interface: Interface) -> bool:
    counters = (
        interface.errors.crc,
        interface.errors.rx,
        interface.errors.tx,
        interface.statistics.rx_drops,
        interface.statistics.tx_drops,
        interface.statistics.collisions,
    )
    return any(value is not None and value > 0 for value in counters)


__all__ = ["HA_CORRELATION_WINDOW_SECONDS", "correlate_ha_diagnostics"]
