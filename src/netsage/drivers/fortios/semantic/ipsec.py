"""Parse FortiOS IKE and IPsec status without retaining key material."""

import re
from ipaddress import IPv4Network, IPv6Network, ip_network

from netsage.drivers.fortios.semantic.common import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
    bounded_tuple,
    endpoint_address,
    parse_duration_seconds,
    require_recognizable_output,
)
from netsage.models import (
    FeatureState,
    IPsecPhase1,
    IPsecPhase2,
    IPsecPhaseState,
    IPsecStatus,
    IPsecTunnel,
    SemanticParserMetadata,
    SemanticParserState,
)
from netsage.models.observability import (
    MAX_IPSEC_PHASE1,
    MAX_IPSEC_PHASE2_PER_TUNNEL,
    MAX_IPSEC_TUNNELS,
)

_NOT_CONFIGURED = re.compile(r"(?i)(?:ipsec|ike).*(?:not configured|no configuration)")
_DISABLED = re.compile(r"(?i)(?:ipsec|ike).*(?:disabled|not enabled|not running)")


def parse_ipsec_status(
    device_id: str,
    phase1_output: str,
    tunnel_output: str,
    *,
    variant: str = "ipsec-status-v1",
) -> IPsecStatus:
    combined = "\n".join((phase1_output, tunnel_output)).strip()
    if not combined:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.EMPTY_OUTPUT,
            "FortiOS IPsec output was empty",
        )
    if _NOT_CONFIGURED.search(combined):
        return IPsecStatus(
            device_id=device_id,
            enabled=False,
            feature_state=FeatureState.NOT_CONFIGURED,
            parser=_metadata(variant, partial=False),
        )
    if _DISABLED.search(combined):
        return IPsecStatus(
            device_id=device_id,
            enabled=False,
            feature_state=FeatureState.DISABLED,
            parser=_metadata(variant, partial=False),
        )
    phase1_text = (
        require_recognizable_output(phase1_output, "IKE gateway") if phase1_output.strip() else ""
    )
    tunnel_text = (
        require_recognizable_output(tunnel_output, "IPsec tunnel") if tunnel_output.strip() else ""
    )
    phase1, phase1_truncated = bounded_tuple(
        _parse_phase1(device_id, phase1_text), MAX_IPSEC_PHASE1
    )
    phase1_by_name = {item.name: item for item in phase1}
    tunnels, tunnel_truncated = bounded_tuple(
        _parse_tunnels(device_id, tunnel_text, phase1_by_name), MAX_IPSEC_TUNNELS
    )
    recognized = (
        phase1
        or tunnels
        or "list all ipsec tunnel" in tunnel_text.casefold()
        or "ike sa:" in phase1_text.casefold()
    )
    if not recognized:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS IPsec output was not recognized",
        )
    enabled = True if phase1 or tunnels else None
    partial = (
        enabled is None
        or not phase1
        or not tunnels
        or any(item.state is IPsecPhaseState.UNKNOWN for item in phase1)
        or any(
            tunnel.phase1_state is IPsecPhaseState.UNKNOWN
            or any(phase.state is IPsecPhaseState.UNKNOWN for phase in tunnel.phase2)
            for tunnel in tunnels
        )
    )
    return IPsecStatus(
        device_id=device_id,
        enabled=enabled,
        feature_state=FeatureState.ENABLED if enabled else FeatureState.UNKNOWN,
        parser=_metadata(variant, partial=partial),
        phase1=phase1,
        tunnels=tunnels,
        truncated=phase1_truncated or tunnel_truncated or any(item.truncated for item in tunnels),
    )


def _metadata(variant: str, *, partial: bool) -> SemanticParserMetadata:
    return SemanticParserMetadata(
        state=SemanticParserState.PARTIAL if partial else SemanticParserState.PARSED,
        variant=variant,
        attempted_variants=(variant,),
    )


def _parse_phase1(device_id: str, output: str) -> tuple[IPsecPhase1, ...]:
    blocks = _named_blocks(output, re.compile(r"(?im)^\s*name:\s*(.+?)\s*$"))
    results = []
    for name, block in blocks:
        version = _integer_line(block, "version")
        interface_match = re.search(r"(?im)^\s*interface:\s*([^\s]+)", block)
        peer_match = re.search(r"(?im)^\s*addr:\s*\S+\s*->\s*(\S+)", block)
        created_match = re.search(r"(?im)^\s*created:\s*(.+?)(?:\s+ago)?\s*$", block)
        ike_match = re.search(
            r"(?im)^\s*IKE SA:\s*created\s+(\d+)/(\d+)\s+"
            r"established\s+(\d+)/(\d+)",
            block,
        )
        status_values = re.findall(r"(?im)^\s*status:\s*([^\s]+)", block)
        state = _phase1_state(status_values, ike_match)
        rekey_match = re.search(r"(?im)^\s*lifetime/rekey:\s*\d+/(\d+)", block)
        nat_match = re.search(r"(?im)^\s*nat:\s*(.+)$", block)
        results.append(
            IPsecPhase1(
                device_id=device_id,
                name=name,
                peer=endpoint_address(peer_match.group(1)) if peer_match else None,
                interface=interface_match.group(1) if interface_match else None,
                ike_version=version if version in {1, 2} else None,
                state=state,
                uptime_seconds=(
                    parse_duration_seconds(created_match.group(1)) if created_match else None
                ),
                established_sas=int(ike_match.group(3)) if ike_match else None,
                created_sas=int(ike_match.group(1)) if ike_match else None,
                nat_traversal=(nat_match is not None) or None,
                rekey_seconds=int(rekey_match.group(1)) if rekey_match else None,
            )
        )
    return tuple(results)


def _parse_tunnels(
    device_id: str,
    output: str,
    phase1_by_name: dict[str, IPsecPhase1],
) -> tuple[IPsecTunnel, ...]:
    pattern = re.compile(r"(?im)^\s*name=(\S+)\s+.*$")
    results = []
    for name, block in _named_blocks(output, pattern):
        first_line = block.splitlines()[0]
        version_match = re.search(r"\bver=(\d+)", first_line)
        peer_match = re.search(r"\S+->(?P<peer>\S+)", first_line)
        statistics = re.search(
            r"(?im)^\s*stat:\s*rxp=(\d+)\s+txp=(\d+)\s+rxb=(\d+)\s+txb=(\d+)",
            block,
        )
        natt_match = re.search(r"(?im)^\s*natt:\s*mode=([^\s]+)", block)
        phase1 = phase1_by_name.get(name) or phase1_by_name.get(name.rsplit("_", 1)[0])
        phase2, phase2_truncated = bounded_tuple(
            _parse_phase2(device_id, block), MAX_IPSEC_PHASE2_PER_TUNNEL
        )
        results.append(
            IPsecTunnel(
                device_id=device_id,
                name=name,
                peer=endpoint_address(peer_match.group("peer")) if peer_match else None,
                interface=phase1.interface if phase1 else None,
                ike_version=(int(version_match.group(1)) if version_match else None),
                phase1_state=phase1.state if phase1 else IPsecPhaseState.UNKNOWN,
                phase2=phase2,
                rx_packets=int(statistics.group(1)) if statistics else None,
                tx_packets=int(statistics.group(2)) if statistics else None,
                rx_bytes=int(statistics.group(3)) if statistics else None,
                tx_bytes=int(statistics.group(4)) if statistics else None,
                nat_traversal=(natt_match.group(1).casefold() != "none" if natt_match else None),
                truncated=phase2_truncated,
            )
        )
    return tuple(results)


def _parse_phase2(device_id: str, tunnel_block: str) -> tuple[IPsecPhase2, ...]:
    pattern = re.compile(r"(?im)^\s*proxyid=(\S+)\s+.*$")
    results = []
    for name, block in _named_blocks(tunnel_block, pattern):
        first_line = block.splitlines()[0]
        sa_match = re.search(r"\bsa=(\d+)", first_line)
        sa_count = int(sa_match.group(1)) if sa_match else 0
        protocol_match = re.search(r"\bproto=(\d+)", first_line)
        expire_match = re.search(r"(?im)^\s*SA:.*?\bexpire=(\d+)", block)
        results.append(
            IPsecPhase2(
                device_id=device_id,
                name=name,
                state=_phase2_state(sa_count),
                sa_count=sa_count,
                protocol=int(protocol_match.group(1)) if protocol_match else None,
                source_network=_selector_network(block, "src"),
                destination_network=_selector_network(block, "dst"),
                expires_seconds=int(expire_match.group(1)) if expire_match else None,
            )
        )
    return tuple(results)


def _named_blocks(output: str, pattern: re.Pattern[str]) -> tuple[tuple[str, str], ...]:
    matches = tuple(pattern.finditer(output))
    return tuple(
        (
            match.group(1).strip(),
            output[
                match.start() : matches[index + 1].start() if index + 1 < len(matches) else None
            ],
        )
        for index, match in enumerate(matches)
    )


def _integer_line(block: str, key: str) -> int | None:
    match = re.search(rf"(?im)^\s*{re.escape(key)}:\s*(\d+)", block)
    return int(match.group(1)) if match else None


def _phase1_state(status_values: list[str], ike_match: re.Match[str] | None) -> IPsecPhaseState:
    normalized = {value.casefold() for value in status_values}
    if "established" in normalized:
        return IPsecPhaseState.ESTABLISHED
    if normalized.intersection({"down", "failed", "inactive"}):
        return IPsecPhaseState.DOWN
    if ike_match is not None:
        return IPsecPhaseState.ESTABLISHED if int(ike_match.group(3)) > 0 else IPsecPhaseState.DOWN
    return IPsecPhaseState.UNKNOWN


def _phase2_state(sa_count: int) -> IPsecPhaseState:
    if sa_count == 1:
        return IPsecPhaseState.ESTABLISHED
    if sa_count == 2:
        return IPsecPhaseState.REKEYING
    if sa_count == 0:
        return IPsecPhaseState.DOWN
    return IPsecPhaseState.UNKNOWN


def _selector_network(block: str, label: str) -> IPv4Network | IPv6Network | None:
    match = re.search(
        rf"(?im)^\s*{label}:\s*(?:\d+:)?"
        r"(?P<address>[0-9A-Fa-f:.]+?)/(?P<mask>[0-9.]+)(?::\d+)?\s*$",
        block,
    )
    if match is None:
        return None
    try:
        return ip_network(f"{match.group('address')}/{match.group('mask')}", strict=False)
    except ValueError:
        return None
