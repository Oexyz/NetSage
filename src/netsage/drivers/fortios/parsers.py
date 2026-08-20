"""Pure parsers from sanitized FortiOS text into vendor-neutral models."""

from __future__ import annotations

import re
import shlex
from ipaddress import IPv4Interface, IPv6Interface, ip_address, ip_interface, ip_network

from netsage.models import (
    VLAN,
    ArpEntry,
    DeviceFacts,
    FirewallAction,
    FirewallPolicy,
    HealthStatus,
    Interface,
    InterfaceState,
    PingResult,
    Route,
    SystemHealth,
    TracerouteHop,
    TracerouteResult,
)

_FORTIOS_MODEL_PATTERN_TEXT = r"(?:Forti[A-Za-z0-9_.-]+|FG[A-Za-z0-9_.-]+)"


class FortiOSParseError(ValueError):
    """A bounded parser error which never includes raw device output."""


def parse_device_facts(device_id: str, output: str) -> DeviceFacts:
    values = _parse_key_values(output)
    version_text = _case_insensitive_value(values, "version")
    if not version_text:
        fallback_match = re.search(r"(?im)^\s*version\s*[:=\s]\s*(.+?)\s*$", output)
        if fallback_match:
            version_text = fallback_match.group(1).strip()
    if not version_text:
        # Handle variants that report model+version in one combined line
        # without a dedicated "Version:" key.
        fallback_match = re.search(
            rf"(?im)^(?P<line>.*?{_FORTIOS_MODEL_PATTERN_TEXT}\s+v?"
            rf"(?:\d+\.\d+(?:\.\d+)?).*)$",
            output,
        )
        if fallback_match:
            version_text = fallback_match.group("line").strip()
    if not version_text:
        raise FortiOSParseError("FortiOS status did not contain a version")
    version_match = re.search(r"\b(?:v)?(?P<version>\d+(?:\.\d+){1,2})", version_text)
    if not version_match:
        raise FortiOSParseError("FortiOS version format is unsupported")
    os_version = version_match.group("version")
    model = _case_insensitive_value(values, "model")
    if not model:
        model = _case_insensitive_value(values, "platform")
    if not model:
        model_match = re.search(
            rf"\b(?P<model>{_FORTIOS_MODEL_PATTERN_TEXT})\b",
            version_text,
            flags=re.IGNORECASE,
        )
        model = model_match.group("model") if model_match else None
    if not model:
        raise FortiOSParseError("FortiOS model is missing")
    return DeviceFacts(
        device_id=device_id,
        vendor="Fortinet",
        model=model,
        os_version=os_version,
        hostname=_case_insensitive_value(values, "hostname"),
        operation_mode=_case_insensitive_value(values, "operation mode"),
        ha_mode=_case_insensitive_value(values, "current ha mode")
        or _case_insensitive_value(values, "ha mode"),
        vdom=_case_insensitive_value(values, "current virtual domain"),
    )


def parse_interfaces(
    device_id: str, config_output: str, physical_output: str
) -> tuple[Interface, ...]:
    try:
        blocks = _parse_config_blocks(config_output, "config system interface")
    except FortiOSParseError:
        blocks = ()
    if not blocks:
        blocks = _parse_config_blocks_loosely(config_output)
    try:
        physical = _parse_physical_interfaces(physical_output)
    except FortiOSParseError:
        # Some FortiGate output variants omit interface physical stats; keep interfaces
        # and expose operational state as unknown instead of failing the full snapshot.
        physical = {}
    interfaces = []
    for name, settings in blocks:
        status = settings.get("status", ("up",))[0]
        admin_state = _normalize_interface_state(status, default=InterfaceState.UP)
        physical_values = physical.get(name, {})
        operational_state = _normalize_interface_state(
            physical_values.get("status"), default=InterfaceState.UNKNOWN
        )
        speed_mbps = _parse_speed_mbps(physical_values.get("speed", ""))
        addresses = _interface_addresses(settings.get("ip", ()))
        vlan_values = settings.get("vlanid", ())
        vlans = (int(vlan_values[0]),) if vlan_values else ()
        mtu_values = settings.get("mtu", ())
        interfaces.append(
            Interface(
                device_id=device_id,
                name=name,
                admin_state=admin_state,
                operational_state=operational_state,
                description=_first(settings, "alias") or _first(settings, "description"),
                speed_mbps=speed_mbps,
                mtu=int(mtu_values[0]) if mtu_values else None,
                addresses=addresses,
                vlans=vlans,
            )
        )
    if not interfaces:
        raise FortiOSParseError("FortiOS interface configuration contained no interfaces")
    return tuple(interfaces)


def parse_vlans(device_id: str, config_output: str) -> tuple[VLAN, ...]:
    blocks = _parse_config_blocks(config_output, "config system interface")
    vlans = []
    for name, settings in blocks:
        vlan_values = settings.get("vlanid", ())
        if not vlan_values:
            continue
        vlans.append(
            VLAN(
                device_id=device_id,
                vlan_id=int(vlan_values[0]),
                name=name,
                parent_interface=_first(settings, "interface"),
            )
        )
    return tuple(vlans)


def parse_arp_table(device_id: str, output: str) -> tuple[ArpEntry, ...]:
    if "Hardware Addr" not in output or "Interface" not in output:
        raise FortiOSParseError("FortiOS ARP output header is missing")
    entries = []
    for line in output.splitlines():
        columns = line.split()
        if len(columns) < 4:
            continue
        try:
            address = ip_address(columns[0])
        except ValueError:
            continue
        entries.append(
            ArpEntry(
                device_id=device_id,
                ip_address=address,
                mac_address=columns[2],
                interface=" ".join(columns[3:]),
            )
        )
    return tuple(entries)


def parse_routes(device_id: str, output: str) -> tuple[Route, ...]:
    if "Routing table for VRF=" not in output:
        raise FortiOSParseError("FortiOS routing table header is missing")
    routes = []
    vrf = 0
    previous: tuple[str, str] | None = None
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        vrf_match = re.fullmatch(r"Routing table for VRF=(\d+)", stripped)
        if vrf_match:
            vrf = int(vrf_match.group(1))
            previous = None
            continue
        route_match = re.match(
            r"^(?P<code>.+?)\s+(?P<prefix>[0-9A-Fa-f:.]+/\d+)\s+(?P<rest>.+)$",
            stripped,
        )
        if route_match:
            code = route_match.group("code").strip()
            prefix_text = route_match.group("prefix")
            rest = route_match.group("rest")
            previous = (code, prefix_text)
        elif previous and re.match(r"^\[\d+/\d+\]\s+via\s+", stripped):
            code, prefix_text = previous
            rest = stripped
        else:
            continue
        try:
            prefix = ip_network(prefix_text, strict=False)
        except ValueError:
            continue
        selected = "*" in code or ">" in code
        normalized_code = re.sub(r"[^A-Za-z0-9]+", " ", code).strip()
        protocol = _route_protocol(normalized_code)
        distance, metric = _route_cost(rest)
        interface_name: str | None = None
        next_hop = None
        direct_match = re.search(r"is directly connected,\s*([^,\s]+)", rest)
        if direct_match:
            interface_name = direct_match.group(1)
        else:
            via_match = re.search(r"\bvia\s+(.+)$", rest)
            if via_match:
                via_parts = [part.strip() for part in via_match.group(1).split(",")]
                for token in re.split(r"\s+", via_parts[0]):
                    try:
                        next_hop = ip_address(token)
                    except ValueError:
                        continue
                if len(via_parts) > 1:
                    interface_name = via_parts[1].split()[0]
        routes.append(
            Route(
                device_id=device_id,
                prefix=prefix,
                protocol=protocol,
                next_hop=next_hop,
                interface=interface_name,
                distance=distance,
                metric=metric,
                vrf=vrf,
                selected=selected,
            )
        )
    return tuple(routes)


def parse_system_health(device_id: str, output: str) -> SystemHealth:
    idle_match = re.search(r"(?m)^CPU states:.*?\b(\d+)%\s+idle\b", output)
    memory_match = re.search(r"(?m)^Memory states:\s*(\d+)%\s+used\b", output)
    if not idle_match or not memory_match:
        raise FortiOSParseError("FortiOS performance output is incomplete")
    cpu_percent = float(100 - int(idle_match.group(1)))
    memory_percent = float(memory_match.group(1))
    status = HealthStatus.HEALTHY
    if cpu_percent >= 90 or memory_percent >= 90:
        status = HealthStatus.UNHEALTHY
    elif cpu_percent >= 75 or memory_percent >= 75:
        status = HealthStatus.DEGRADED
    uptime_match = re.search(r"(?m)^Uptime:\s*(.+)$", output)
    uptime_text = uptime_match.group(1).strip() if uptime_match else None
    return SystemHealth(
        device_id=device_id,
        status=status,
        cpu_percent=cpu_percent,
        memory_percent=memory_percent,
        uptime_seconds=_parse_uptime(uptime_text) if uptime_text else None,
        observations=(f"uptime: {uptime_text}",) if uptime_text else (),
    )


def parse_firewall_policies(device_id: str, output: str) -> tuple[FirewallPolicy, ...]:
    blocks = _parse_config_blocks(output, "config firewall policy")
    policies = []
    for policy_id_text, settings in blocks:
        try:
            policy_id = int(policy_id_text)
        except ValueError as error:
            raise FortiOSParseError("FortiOS firewall policy ID is invalid") from error
        action_text = _first(settings, "action") or FirewallAction.DENY.value
        try:
            action = FirewallAction(action_text)
        except ValueError:
            action = FirewallAction.UNKNOWN
        policies.append(
            FirewallPolicy(
                device_id=device_id,
                policy_id=policy_id,
                name=_first(settings, "name"),
                source_interfaces=settings.get("srcintf", ()),
                destination_interfaces=settings.get("dstintf", ()),
                source_addresses=settings.get("srcaddr", ()),
                destination_addresses=settings.get("dstaddr", ()),
                services=settings.get("service", ()),
                action=action,
                enabled=_first(settings, "status") != "disable",
                nat_enabled=_first(settings, "nat") == "enable",
                schedule=_first(settings, "schedule"),
                comments=_first(settings, "comments"),
            )
        )
    return tuple(policies)


def parse_ping_result(device_id: str, destination: str, output: str) -> PingResult:
    stats = re.search(
        r"(?m)(\d+) packets transmitted,\s*(\d+) packets received,\s*"
        r"([\d.]+)% packet loss",
        output,
    )
    if not stats:
        raise FortiOSParseError("FortiOS ping statistics are missing")
    timing = re.search(
        r"(?m)(?:round-trip|rtt) min/avg/max(?:/[^\s=]+)?\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)",
        output,
    )
    return PingResult(
        device_id=device_id,
        destination=ip_address(destination),
        packets_transmitted=int(stats.group(1)),
        packets_received=int(stats.group(2)),
        packet_loss_percent=float(stats.group(3)),
        min_ms=float(timing.group(1)) if timing else None,
        avg_ms=float(timing.group(2)) if timing else None,
        max_ms=float(timing.group(3)) if timing else None,
    )


def parse_traceroute_result(device_id: str, destination: str, output: str) -> TracerouteResult:
    destination_address = ip_address(destination)
    hops = []
    for line in output.splitlines():
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue
        hop_number = int(match.group(1))
        remainder = match.group(2)
        addresses = []
        for token in re.split(r"[\s()]", remainder):
            try:
                addresses.append(ip_address(token))
            except ValueError:
                continue
        rtts = tuple(float(value) for value in re.findall(r"([\d.]+)\s*ms", remainder))
        timed_out = "*" in remainder and not addresses
        hops.append(
            TracerouteHop(
                hop=hop_number,
                address=addresses[-1] if addresses else None,
                rtt_ms=rtts,
                timed_out=timed_out,
            )
        )
    if not hops:
        raise FortiOSParseError("FortiOS traceroute contained no hops")
    return TracerouteResult(
        device_id=device_id,
        destination=destination_address,
        hops=tuple(hops),
        reached=hops[-1].address == destination_address,
    )


def _parse_key_values(output: str) -> dict[str, str]:
    values = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if not separator and "=" in line:
            key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def _case_insensitive_value(mapping: dict[str, str], key: str) -> str | None:
    explicit = mapping.get(key)
    if explicit:
        return explicit
    normalized = key.casefold()
    for candidate_key, candidate_value in mapping.items():
        if candidate_key.casefold() == normalized:
            return candidate_value
    return None


def _parse_config_blocks(
    output: str, expected_header: str
) -> tuple[tuple[str, dict[str, tuple[str, ...]]], ...]:
    normalized_expected_header = expected_header.casefold()
    if normalized_expected_header not in output.casefold():
        raise FortiOSParseError("FortiOS configuration header is missing")
    blocks = []
    current_name: str | None = None
    settings: dict[str, tuple[str, ...]] = {}
    in_context = False
    depth = 0
    for raw_line in output.splitlines():
        line = _normalize_line(raw_line)
        if _config_header_matches(line, expected_header):
            in_context = True
            depth = 1
            continue
        if not in_context:
            continue
        if line.startswith("config "):
            depth += 1
            continue
        if line == "end":
            depth -= 1
            if depth == 0:
                in_context = False
                break
            continue
        if depth != 1:
            continue
        if line.startswith("edit "):
            if current_name is not None:
                blocks.append((current_name, settings))
            current_name = _split_cli(line[5:])[0]
            settings = {}
        elif line.startswith("set ") and current_name is not None:
            values = _split_cli(line[4:])
            if len(values) >= 2:
                settings[values[0]] = tuple(values[1:])
        elif line == "next" and current_name is not None:
            blocks.append((current_name, settings))
            current_name = None
            settings = {}
    if current_name is not None:
        blocks.append((current_name, settings))
    return tuple(blocks)


def _parse_config_blocks_loosely(
    output: str,
) -> tuple[tuple[str, dict[str, tuple[str, ...]]], ...]:
    """Parse config-style output that contains edit/set/next blocks without header."""

    blocks = []
    current_name: str | None = None
    settings: dict[str, tuple[str, ...]] = {}
    depth = 0
    in_block = False
    for raw_line in output.splitlines():
        line = _normalize_line(raw_line)
        if _config_header_matches(line, "config system interface"):
            in_block = True
            depth = 0
            if current_name is not None:
                blocks.append((current_name, settings))
                current_name = None
                settings = {}
            continue
        if line.startswith("edit "):
            if depth == 0:
                if in_block and current_name is not None:
                    blocks.append((current_name, settings))
                current_name = _split_cli(line[5:])[0]
                settings = {}
                in_block = True
            continue
        if not in_block:
            continue
        if line.startswith("config "):
            depth += 1
            continue
        if line == "end":
            if depth > 0:
                depth -= 1
            elif current_name is not None:
                blocks.append((current_name, settings))
                in_block = False
                current_name = None
                settings = {}
            continue
        if depth > 0:
            continue
        elif line.startswith("set ") and current_name is not None:
            values = _split_cli(line[4:])
            if len(values) >= 2:
                settings[values[0]] = tuple(values[1:])
        elif line == "next" and current_name is not None:
            blocks.append((current_name, settings))
            in_block = False
            current_name = None
            settings = {}
            continue
        elif line == "end" and current_name is not None:
            blocks.append((current_name, settings))
            in_block = False
            current_name = None
            settings = {}
    if current_name is not None:
        blocks.append((current_name, settings))
    return tuple(blocks)


def _config_header_matches(line: str, expected_header: str) -> bool:
    normalized_line = " ".join(line.casefold().split())
    normalized_expected = " ".join(expected_header.casefold().split())
    return (
        normalized_line == normalized_expected
        or normalized_line.startswith(normalized_expected + " ")
        or normalized_line.endswith(" " + normalized_expected)
    )


def _split_cli(value: str) -> list[str]:
    try:
        return shlex.split(value, posix=True)
    except ValueError as error:
        raise FortiOSParseError("FortiOS quoted configuration value is invalid") from error


def _parse_physical_interfaces(output: str) -> dict[str, dict[str, str]]:
    if "==" not in output:
        raise FortiOSParseError("FortiOS physical interface output is missing")
    interfaces: dict[str, dict[str, str]] = {}
    current: dict[str, str] | None = None
    for raw_line in output.splitlines():
        normalized_line = _normalize_line(raw_line)
        header = re.fullmatch(r"\s*==\s*\[([^]]+)]\s*", normalized_line)
        if header:
            name = header.group(1).strip()
            if name.lower() == "onboard":
                current = None
            else:
                current = interfaces.setdefault(name, {})
            continue
        if current is not None:
            key, separator, value = normalized_line.partition(":")
            if not separator:
                key, separator, value = normalized_line.partition("=")
            if separator:
                current[key.strip()] = value.strip()
    return interfaces


def _normalize_line(line: str) -> str:
    return line.removeprefix("\ufeff").strip()


def _interface_addresses(values: tuple[str, ...]) -> tuple[IPv4Interface | IPv6Interface, ...]:
    if len(values) < 2:
        return ()
    try:
        if ip_address(values[0]).is_unspecified:
            return ()
        return (ip_interface(f"{values[0]}/{values[1]}"),)
    except ValueError as error:
        raise FortiOSParseError("FortiOS interface address is invalid") from error


def _parse_speed_mbps(raw: str | None) -> int | None:
    if raw is None:
        return None
    match = re.search(r"(?i)^(?P<value>\d+)\s*(?P<unit>gbps?|mbps?|m|g)?\b", raw.strip())
    if not match:
        return None
    speed = int(match.group("value"))
    if speed <= 0:
        return None
    unit = (match.group("unit") or "").casefold()
    if unit.startswith("g"):
        return speed * 1000
    return speed


def _normalize_interface_state(value: str | None, *, default: InterfaceState) -> InterfaceState:
    if value is None:
        return default
    normalized = value.casefold().strip()
    if "down" in normalized or "disable" in normalized:
        return InterfaceState.DOWN
    if "up" in normalized:
        return InterfaceState.UP
    return default


def _first(settings: dict[str, tuple[str, ...]], key: str) -> str | None:
    values = settings.get(key, ())
    return values[0] if values else None


def _route_protocol(code: str) -> str:
    prefix = code.split()[0] if code else "unknown"
    return {
        "K": "kernel",
        "C": "connected",
        "S": "static",
        "R": "rip",
        "B": "bgp",
        "O": "ospf",
        "IA": "ospf_inter_area",
        "N1": "ospf_nssa_external_1",
        "N2": "ospf_nssa_external_2",
        "E1": "ospf_external_1",
        "E2": "ospf_external_2",
        "i": "isis",
    }.get(prefix, prefix.lower())


def _route_cost(rest: str) -> tuple[int | None, int | None]:
    match = re.search(r"\[(\d+)/(\d+)]", rest)
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))


def _parse_uptime(value: str) -> int | None:
    units = {
        "day": 86400,
        "days": 86400,
        "hour": 3600,
        "hours": 3600,
        "minute": 60,
        "minutes": 60,
        "min": 60,
        "mins": 60,
        "second": 1,
        "seconds": 1,
    }
    total = 0
    found = False
    for amount, unit in re.findall(r"(\d+)\s+([A-Za-z]+)", value):
        multiplier = units.get(unit.lower())
        if multiplier is not None:
            total += int(amount) * multiplier
            found = True
    return total if found else None
