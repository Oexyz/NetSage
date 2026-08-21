"""Deterministic extractor for the converted FortiOS 7.2.13 CLI reference."""

from __future__ import annotations

import gzip
import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from netsage.drivers.fortios.catalog.models import (
    FortiOSArgumentDefinition,
    FortiOSArgumentKind,
    FortiOSCatalogCoverage,
    FortiOSCommandContext,
    FortiOSCommandDefinition,
    FortiOSCommandManifest,
    FortiOSExecutionSupport,
    FortiOSParserSupport,
    FortiOSSourceReference,
)
from netsage.models import Capability
from netsage.policies import OperationClass

GENERATED_NOTICE: Final = "DO NOT EDIT MANUALLY. Generated from fortios.md."
_ROOT_VERBS = {"config", "diagnose", "execute"}
_CONFIG_VERBS = {
    "append",
    "config",
    "delete",
    "edit",
    "end",
    "move",
    "next",
    "purge",
    "rename",
    "select",
    "set",
    "unset",
    "unselect",
}
_ALL_VERBS = _ROOT_VERBS | _CONFIG_VERBS
_TABLE_METADATA = {"Default", "Description", "Option", "Parameter", "Size", "Type"}
_SEPARATOR = re.compile(r"^:?-{3,}:?$")
_TOPIC = re.compile(r"l\s+((?:config|diagnose|execute)[^\s]*?)onpage(\d+)", re.IGNORECASE)
_PAGE = re.compile(r"FortiOS\s*7\.2\.13\s*CLI\s*Reference\s+(\d+)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"(<[^>]+>|\{[^}]+\}|\[[^]]+\])")
_SAFE_SYNTAX = re.compile(r"^[A-Za-z0-9_./,:+%{}<>\[\]|@*?= -]+$")
_DESTRUCTIVE_WORDS = {
    "clear",
    "delete",
    "disconnect",
    "downgrade",
    "erase",
    "factoryreset",
    "failover",
    "firmware",
    "format",
    "kill",
    "reboot",
    "reload",
    "remove",
    "reset",
    "restart",
    "restore",
    "shutdown",
    "terminate",
    "upgrade",
    "wipe",
}
_READ_ONLY_WORDS = {
    "check",
    "display",
    "dump",
    "get",
    "info",
    "information",
    "list",
    "lookup",
    "read",
    "show",
    "status",
    "statistics",
    "view",
}
_DESCRIPTION_READ_PREFIXES = (
    "check",
    "display",
    "dump",
    "get",
    "list",
    "print",
    "show",
    "view",
)
_DESCRIPTION_DESTRUCTIVE = (
    "clear",
    "delete",
    "disconnect",
    "downgrade",
    "erase",
    "factoryreset",
    "format",
    "kill",
    "reboot",
    "remove",
    "reset",
    "restart",
    "restore",
    "shutdown",
    "terminate",
    "upgrade",
    "wipe",
)
_STRUCTURED_COMMANDS = {
    "execute ping": (Capability.PING, FortiOSParserSupport.TYPED),
    "execute traceroute": (Capability.TRACEROUTE, FortiOSParserSupport.TYPED),
}


@dataclass(frozen=True, slots=True)
class _Topic:
    source_key: str
    page: int
    listing_line: int
    label: str


@dataclass(frozen=True, slots=True)
class _Candidate:
    line: int
    syntax: str
    literal_path: str
    source_key: str
    description: str | None


def build_manifest(source_path: Path) -> FortiOSCommandManifest:
    source_bytes = source_path.read_bytes()
    lines = source_bytes.decode("utf-8-sig").splitlines()
    markers = _section_markers(lines)
    pages = _page_by_line(lines)

    topic_definitions: list[FortiOSCommandDefinition] = []
    config_topics: list[tuple[_Topic, _Candidate]] = []
    source_topic_count = 0
    source_syntax_count = 0
    source_artifact_count = 0
    config_candidates: dict[str, list[_Candidate]] = {}
    config_topic_keys: set[str] = set()
    for section in ("config", "diagnose", "execute"):
        start, end = markers[section]
        topics = _topics(lines, start=start, end=end, section=section)
        candidates = _root_candidates(lines, start=start, end=end, section=section)
        if section == "config":
            config_candidates = candidates
            config_topic_keys = {topic.source_key for topic in topics}
        for topic in topics:
            candidate = _select_candidate(topic, candidates)
            definition = _definition_from_topic(topic, candidate, section=section)
            topic_definitions.append(definition)
            source_topic_count += 1
            if section == "config":
                config_topics.append((topic, candidate))
        if section in {"diagnose", "execute"}:
            topic_keys = {topic.source_key for topic in topics}
            for source_key in sorted(set(candidates) - topic_keys):
                candidate = _select_syntax_candidate(candidates[source_key])
                if not _valid_syntax_derived_candidate(candidate):
                    source_artifact_count += 1
                    continue
                topic_definitions.append(
                    _definition_from_topic(
                        _Topic(
                            source_key=source_key,
                            page=pages[candidate.line] or 1,
                            listing_line=candidate.line - 1,
                            label=candidate.literal_path,
                        ),
                        candidate,
                        section=f"{section}-syntax",
                    )
                )
                source_syntax_count += 1

    context_definitions = _configuration_context_definitions(
        lines,
        pages=pages,
        topics=config_topics,
        section_end=markers["config"][1],
    )
    source_artifact_count += _validate_config_candidate_coverage(
        candidates=config_candidates,
        topic_keys=config_topic_keys,
        context_definitions=context_definitions,
    )
    definitions = _deduplicate_ids(topic_definitions + context_definitions)
    definitions.sort(key=lambda definition: definition.id)
    coverage = _coverage(
        definitions,
        topic_count=source_topic_count,
        syntax_count=source_syntax_count,
        artifact_count=source_artifact_count,
    )
    return FortiOSCommandManifest(
        generated_notice=GENERATED_NOTICE,
        source_document=source_path.name,
        source_sha256=hashlib.sha256(source_bytes).hexdigest(),
        source_bytes=len(source_bytes),
        source_lines=len(lines),
        fortios_version="7.2.13",
        coverage=coverage,
        definitions=tuple(definitions),
    )


def manifest_json_bytes(manifest: FortiOSCommandManifest) -> bytes:
    payload = manifest.model_dump(mode="json")
    return (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
    ).encode("utf-8")


def compressed_manifest_bytes(manifest: FortiOSCommandManifest) -> bytes:
    return gzip.compress(manifest_json_bytes(manifest), compresslevel=9, mtime=0)


def coverage_markdown(manifest: FortiOSCommandManifest) -> str:
    coverage = manifest.coverage
    source_hash = manifest.source_sha256
    return f"""# FortiOS Command Catalog Coverage

<!-- {GENERATED_NOTICE} -->

Source: `fortios.md` (FortiOS {manifest.fortios_version}, SHA-256 `{source_hash}`)

| Metric | Count |
|---|---:|
| Source topic commands | {coverage.source_topic_commands} |
| Source additional syntax commands | {coverage.source_syntax_commands} |
| Source configuration-context commands | {coverage.source_context_commands} |
| Source conversion/non-command artifacts | {coverage.source_non_command_artifacts} |
| Commands discovered | {coverage.commands_discovered} |
| Commands catalogued | {coverage.commands_catalogued} |
| Source definitions uncatalogued | {coverage.source_definitions_uncatalogued} |
| Read-only | {coverage.read_only} |
| Diagnostic | {coverage.diagnostic} |
| Configuration | {coverage.configuration} |
| Destructive | {coverage.destructive} |
| Structured executable | {coverage.structured_executable} |
| Executable in default Observe | {coverage.executable_in_observe} |
| Typed output parsers | {coverage.typed_parsers} |
| Sanitized-text parsers | {coverage.sanitized_text_parsers} |
| Catalog-only | {coverage.catalog_only} |

Catalog coverage is 100% of definitions discovered by the checked-in extractor.
This is command-knowledge coverage, not full execution or typed-parser support.
Configuration and destructive definitions remain denied in Observe mode. The
generated runtime manifest is never exposed wholesale to an AI provider.
"""


def _section_markers(lines: list[str]) -> dict[str, tuple[int, int]]:
    starts: dict[str, int] = {}
    included_devices: int | None = None
    wanted = {
        "cliconfigurationcommands": "config",
        "clidiagnosecommands": "diagnose",
        "cliexecutecommands": "execute",
    }
    for line_number, line in enumerate(lines, 1):
        compact = re.sub(r"[^a-z]", "", line.lower())
        section = wanted.get(compact)
        if section is not None and line_number > 5_600 and section not in starts:
            starts[section] = line_number
        if compact == "includeddevices" and line_number > 130_000:
            included_devices = line_number
            break
    if set(starts) != set(wanted.values()) or included_devices is None:
        raise ValueError("FortiOS CLI source section boundaries were not found")
    if not (starts["config"] < starts["diagnose"] < starts["execute"] < included_devices):
        raise ValueError("FortiOS CLI source sections are out of order")
    return {
        "config": (starts["config"], starts["diagnose"]),
        "diagnose": (starts["diagnose"], starts["execute"]),
        "execute": (starts["execute"], included_devices),
    }


def _page_by_line(lines: list[str]) -> tuple[int | None, ...]:
    pages: list[int | None] = [None] * (len(lines) + 1)
    next_page: int | None = None
    for line_number in range(len(lines), 0, -1):
        match = _PAGE.search(lines[line_number - 1].replace("Â", ""))
        if match:
            next_page = int(match.group(1))
        pages[line_number] = next_page
    return tuple(pages)


def _topics(lines: list[str], *, start: int, end: int, section: str) -> list[_Topic]:
    topics: list[_Topic] = []
    for line_number in range(start, end):
        match = _TOPIC.fullmatch(lines[line_number - 1].strip())
        if match is None:
            continue
        label = match.group(1)
        if not label.lower().startswith(section):
            continue
        topics.append(
            _Topic(
                source_key=_source_key(label),
                page=int(match.group(2)),
                listing_line=line_number,
                label=label,
            )
        )
    if len(topics) != len({topic.source_key for topic in topics}):
        raise ValueError(f"duplicate FortiOS {section} source topic key")
    return topics


def _root_candidates(
    lines: list[str], *, start: int, end: int, section: str
) -> dict[str, list[_Candidate]]:
    candidates: dict[str, list[_Candidate]] = defaultdict(list)
    for line_number in range(start, end):
        syntax = _command_expression(lines[line_number - 1], allowed_verbs=_ALL_VERBS)
        if syntax is None or syntax.split(maxsplit=1)[0].lower() != section:
            continue
        literal_path = _literal_path(syntax)
        candidate = _Candidate(
            line=line_number,
            syntax=syntax,
            literal_path=literal_path,
            source_key=_source_key(literal_path),
            description=_nearby_description(lines, line_number),
        )
        candidates[candidate.source_key].append(candidate)
    return dict(candidates)


def _select_candidate(topic: _Topic, candidates: dict[str, list[_Candidate]]) -> _Candidate:
    matches = [
        candidate
        for candidate in candidates.get(topic.source_key, ())
        if candidate.line > topic.listing_line
    ]
    if not matches:
        raise ValueError(f"FortiOS source topic has no syntax: {topic.label}")
    return max(
        matches,
        key=lambda candidate: (
            len(_argument_definitions(candidate.syntax)),
            len(candidate.syntax),
            -candidate.line,
        ),
    )


def _select_syntax_candidate(candidates: list[_Candidate]) -> _Candidate:
    return max(
        candidates,
        key=lambda candidate: (
            len(_argument_definitions(candidate.syntax)),
            len(candidate.syntax),
            -candidate.line,
        ),
    )


def _valid_syntax_derived_candidate(candidate: _Candidate) -> bool:
    return (
        len(candidate.literal_path.split()) >= 2
        and not candidate.literal_path.endswith("-")
        and not candidate.syntax.endswith(".")
    )


def _validate_config_candidate_coverage(
    *,
    candidates: dict[str, list[_Candidate]],
    topic_keys: set[str],
    context_definitions: list[FortiOSCommandDefinition],
) -> int:
    context_keys = {
        _source_key(definition.path)
        for definition in context_definitions
        if definition.path.startswith("config ")
    }
    artifact_count = 0
    for source_key in sorted(set(candidates) - topic_keys):
        if source_key in context_keys:
            continue
        values = candidates[source_key]
        if all(
            candidate.literal_path == "config"
            or "." in candidate.syntax
            or "&" in candidate.syntax
            or candidate.literal_path.endswith("-")
            for candidate in values
        ):
            artifact_count += 1
            continue
        raise ValueError(
            f"FortiOS configuration syntax is not represented in catalog: {source_key}"
        )
    return artifact_count


def _definition_from_topic(
    topic: _Topic,
    candidate: _Candidate,
    *,
    section: str,
) -> FortiOSCommandDefinition:
    command_class = _classify(
        candidate.literal_path,
        section=section,
        description=candidate.description,
    )
    execution_support, parser_support = _execution_support(candidate.literal_path)
    arguments = _argument_definitions(candidate.syntax)
    return FortiOSCommandDefinition(
        id=_definition_id(candidate.literal_path),
        path=candidate.literal_path,
        syntax=candidate.syntax,
        # Description prose is used transiently for conservative classification
        # but is not copied into the public generated artifact.
        description=None,
        command_class=command_class,
        capability=_capability(candidate.literal_path),
        context=_command_context(candidate.literal_path, section=section),
        arguments=arguments,
        renderable=_is_renderable(candidate.syntax, arguments),
        observe_allowed=command_class is OperationClass.READ_ONLY,
        execution_support=execution_support,
        parser_support=parser_support,
        source=FortiOSSourceReference(
            line=candidate.line,
            page=topic.page,
            section=section,
        ),
    )


def _configuration_context_definitions(
    lines: list[str],
    *,
    pages: tuple[int | None, ...],
    topics: list[tuple[_Topic, _Candidate]],
    section_end: int,
) -> list[FortiOSCommandDefinition]:
    roots = sorted(topics, key=lambda item: _first_candidate_line(item[0], item[1], lines))
    definitions: list[FortiOSCommandDefinition] = []
    seen: set[tuple[str, str]] = set()
    for index, (topic, selected) in enumerate(roots):
        root_line = _first_candidate_line(topic, selected, lines)
        stop = (
            _first_candidate_line(roots[index + 1][0], roots[index + 1][1], lines)
            if index + 1 < len(roots)
            else section_end
        )
        root_path = selected.literal_path
        stack = [root_path]
        for line_number in range(root_line + 1, stop):
            syntax = _command_expression(lines[line_number - 1], allowed_verbs=_CONFIG_VERBS)
            if syntax is None:
                continue
            verb = syntax.split(maxsplit=1)[0].lower()
            literal_path = _literal_path(syntax)
            if verb == "config":
                if _source_key(literal_path) == topic.source_key:
                    continue
                if not stack:
                    continue
                parent_scope = " > ".join(stack)
                stack.append(literal_path)
                key = (parent_scope, syntax)
                if key not in seen:
                    seen.add(key)
                    definitions.append(
                        _context_definition(
                            path=literal_path,
                            syntax=syntax,
                            scope=parent_scope,
                            line=line_number,
                            page=pages[line_number],
                        )
                    )
                continue
            if verb == "end":
                if not stack:
                    continue
                scope = " > ".join(stack)
                key = (scope, syntax)
                if key not in seen:
                    seen.add(key)
                    definitions.append(
                        _context_definition(
                            path=literal_path,
                            syntax=syntax,
                            scope=scope,
                            line=line_number,
                            page=pages[line_number],
                        )
                    )
                stack.pop()
                if not stack:
                    # The first top-level `end` closes the documented syntax.
                    # Remaining lines on the page are parameter reference tables,
                    # not additional command-tree definitions.
                    break
                continue
            if not stack:
                continue
            if verb == "delete" and syntax.endswith("."):
                continue
            scope = " > ".join(stack)
            key = (scope, syntax)
            if key in seen:
                continue
            seen.add(key)
            definitions.append(
                _context_definition(
                    path=literal_path,
                    syntax=syntax,
                    scope=scope,
                    line=line_number,
                    page=pages[line_number],
                )
            )
    return definitions


def _first_candidate_line(topic: _Topic, selected: _Candidate, lines: list[str]) -> int:
    for line_number in range(topic.listing_line + 1, selected.line + 1):
        syntax = _command_expression(lines[line_number - 1], allowed_verbs={"config"})
        if syntax is not None and _source_key(_literal_path(syntax)) == topic.source_key:
            return line_number
    return selected.line


def _context_definition(
    *,
    path: str,
    syntax: str,
    scope: str,
    line: int,
    page: int | None,
) -> FortiOSCommandDefinition:
    arguments = _argument_definitions(syntax)
    verb = path.split(maxsplit=1)[0].lower()
    command_class = (
        OperationClass.DESTRUCTIVE if verb in {"delete", "purge"} else OperationClass.CONFIGURATION
    )
    return FortiOSCommandDefinition(
        id=_definition_id(f"{scope}::{path}"),
        path=path,
        syntax=syntax,
        scope=scope,
        command_class=command_class,
        capability=_capability(scope),
        context=FortiOSCommandContext.CONFIGURATION,
        arguments=arguments,
        renderable=_is_renderable(syntax, arguments),
        observe_allowed=False,
        source=FortiOSSourceReference(line=line, page=page, section="config-context"),
    )


def _command_expression(line: str, *, allowed_verbs: set[str]) -> str | None:
    value = line.strip()
    if not value:
        return None
    if value.startswith("|") and value.endswith("|"):
        cells = [cell.strip() for cell in value[1:-1].split("|")]
        start = next(
            (
                index
                for index, cell in enumerate(cells)
                if cell and cell.split(maxsplit=1)[0] in allowed_verbs
            ),
            None,
        )
        if start is None:
            return None
        selected: list[str] = []
        for cell in cells[start:]:
            if not cell or _SEPARATOR.fullmatch(cell):
                continue
            if cell in _TABLE_METADATA:
                break
            selected.append(cell)
        value = " ".join(selected)
    tokens = value.split()
    if not tokens or tokens[0] not in allowed_verbs:
        return None
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized or "Description:" in normalized:
        return None
    return normalized


def _literal_path(syntax: str) -> str:
    argument_positions = [position for marker in "<[{" if (position := syntax.find(marker)) >= 0]
    without_arguments = syntax[: min(argument_positions)] if argument_positions else syntax
    literal_tokens: list[str] = []
    for token in without_arguments.split():
        cleaned = re.sub(r"[^A-Za-z0-9_-]", "", token)
        if cleaned:
            literal_tokens.append(cleaned)
    return " ".join(literal_tokens)


def _source_key(value: str) -> str:
    return re.sub(r"[^a-z0-9-]", "", value.lower())


def _definition_id(value: str) -> str:
    normalized = value.lower().replace(" > ", ".").replace("::", ":")
    normalized = re.sub(r"\s+", ".", normalized)
    normalized = re.sub(r"[^a-z0-9_.:-]", "", normalized)
    normalized = re.sub(r"\.{2,}", ".", normalized).strip(".")
    if not normalized.startswith("fortios."):
        normalized = f"fortios.{normalized}"
    return normalized[:768]


def _deduplicate_ids(
    definitions: list[FortiOSCommandDefinition],
) -> list[FortiOSCommandDefinition]:
    result: list[FortiOSCommandDefinition] = []
    used: set[str] = set()
    for definition in definitions:
        identifier = definition.id
        if identifier in used:
            digest = hashlib.sha256(
                f"{definition.scope}\0{definition.syntax}".encode()
            ).hexdigest()[:12]
            identifier = f"{identifier[:754]}:{digest}"
            definition = definition.model_copy(update={"id": identifier})
        if identifier in used:
            raise ValueError(f"duplicate FortiOS command ID after disambiguation: {identifier}")
        used.add(identifier)
        result.append(definition)
    return result


def _argument_definitions(syntax: str) -> tuple[FortiOSArgumentDefinition, ...]:
    arguments: list[FortiOSArgumentDefinition] = []
    names: Counter[str] = Counter()
    for placeholder in _PLACEHOLDER.findall(syntax):
        content = placeholder[1:-1].strip()
        if not content:
            continue
        base_name = re.sub(r"[^a-z0-9]+", "-", content.lower()).strip("-") or "value"
        base_name = base_name[:110]
        names[base_name] += 1
        name = base_name if names[base_name] == 1 else f"{base_name}-{names[base_name]}"
        choices = _choices(content)
        kind = _argument_kind(content, choices=choices)
        sensitive = any(
            marker in content.lower()
            for marker in ("password", "passwd", "private-key", "secret", "token")
        )
        arguments.append(
            FortiOSArgumentDefinition(
                name=name,
                placeholder=placeholder,
                kind=kind,
                required="enter" not in content.lower() and "return" not in content.lower(),
                choices=choices,
                sensitive=sensitive,
            )
        )
    return tuple(arguments)


def _choices(content: str) -> tuple[str, ...]:
    if "|" in content:
        values = tuple(
            value.strip()
            for value in content.split("|")
            if value.strip() and value.strip() not in {"...", "Enter", "return"}
        )
        return values if len(values) >= 2 else ()
    if " " in content and all(
        re.fullmatch(r"[A-Za-z0-9_.:+/-]+", item) for item in content.split()
    ):
        values = tuple(content.split())
        return values if len(values) >= 2 and len(values) <= 32 else ()
    return ()


def _argument_kind(content: str, *, choices: tuple[str, ...]) -> FortiOSArgumentKind:
    lowered = content.lower()
    if choices:
        choice_set = {choice.lower() for choice in choices}
        if choice_set in ({"enable", "disable"}, {"on", "off"}, {"yes", "no"}):
            return FortiOSArgumentKind.BOOLEAN
        return FortiOSArgumentKind.ENUM
    if "ipv6" in lowered or "xxxx:xxxx" in lowered:
        return FortiOSArgumentKind.IPV6_ADDRESS
    if "ipv4" in lowered or "xxx.xxx.xxx.xxx" in lowered:
        return FortiOSArgumentKind.IPV4_ADDRESS
    if lowered in {"address", "dest", "destination", "ip", "ip-address"}:
        return FortiOSArgumentKind.IP_ADDRESS
    if any(marker in lowered for marker in ("subnet", "cidr", "netmask", "network")):
        return FortiOSArgumentKind.NETWORK
    if any(marker in lowered for marker in ("integer", "int", "number")):
        return FortiOSArgumentKind.INTEGER
    if "policy" in lowered and "id" in lowered:
        return FortiOSArgumentKind.POLICY_ID
    if lowered == "port" or lowered.endswith("-port"):
        return FortiOSArgumentKind.PORT
    if "interface" in lowered:
        return FortiOSArgumentKind.INTERFACE
    if "vdom" in lowered or lowered == "vd":
        return FortiOSArgumentKind.VDOM
    if "protocol" in lowered or lowered == "proto":
        return FortiOSArgumentKind.PROTOCOL
    if any(marker in lowered for marker in ("fqdn", "hostname", "host")):
        return FortiOSArgumentKind.HOSTNAME
    return FortiOSArgumentKind.STRING


def _is_renderable(syntax: str, arguments: tuple[FortiOSArgumentDefinition, ...]) -> bool:
    if not _SAFE_SYNTAX.fullmatch(syntax):
        return False
    if any(argument.sensitive for argument in arguments):
        return False
    without_arguments = _PLACEHOLDER.sub("", syntax)
    if any(marker in without_arguments for marker in "<>{}[]"):
        return False
    return all("..." not in argument.choices for argument in arguments)


def _classify(path: str, *, section: str, description: str | None) -> OperationClass:
    if section.removesuffix("-syntax") == "config":
        return OperationClass.CONFIGURATION
    words = {word for token in path.lower().split() for word in re.split(r"[-_]", token) if word}
    description_key = re.sub(r"[^a-z]", "", (description or "").lower())
    option_reset = any(marker in path.lower() for marker in ("ping-options", "traceroute-options"))
    if (
        words & _DESTRUCTIVE_WORDS
        or any(marker in description_key for marker in _DESCRIPTION_DESTRUCTIVE)
    ) and not option_reset:
        return OperationClass.DESTRUCTIVE
    if words & _READ_ONLY_WORDS or description_key.startswith(_DESCRIPTION_READ_PREFIXES):
        return OperationClass.READ_ONLY
    return OperationClass.DIAGNOSTIC


def _capability(path: str) -> Capability | None:
    lowered = path.lower()
    rules = (
        (("ping",), Capability.PING),
        (("traceroute",), Capability.TRACEROUTE),
        (("bgp",), Capability.BGP),
        (("ospf",), Capability.OSPF),
        (("route", "router", "routing"), Capability.ROUTES),
        (("arp",), Capability.ARP),
        (("lldp",), Capability.LLDP),
        (("interface", "port"), Capability.INTERFACES),
        (("vlan",), Capability.VLANS),
        (("mac",), Capability.MAC_TABLE),
        (("sdwan", "sd-wan"), Capability.SDWAN),
        (("sslvpn", "ssl-vpn"), Capability.SSL_VPN),
        (("ipsec", "ike"), Capability.IPSEC),
        (("dhcp",), Capability.DHCP),
        (("dns",), Capability.DNS),
        (("session",), Capability.SESSIONS),
        ((" ha ", "high-availability"), Capability.HA),
        (("log",), Capability.LOGS),
        (("vpn",), Capability.VPN),
        (("firewall", "policy", "ips", "antivirus", "webfilter"), Capability.FIREWALL),
        (("system", "hardware", "performance", "health"), Capability.SYSTEM_HEALTH),
    )
    for markers, capability in rules:
        if any(marker in lowered for marker in markers):
            return capability
    return None


def _command_context(path: str, *, section: str) -> FortiOSCommandContext:
    lowered = path.lower()
    if section.removesuffix("-syntax") == "config":
        return FortiOSCommandContext.CONFIGURATION
    if " global" in f" {lowered}":
        return FortiOSCommandContext.GLOBAL
    if " vdom" in f" {lowered}" or " vd " in f" {lowered} ":
        return FortiOSCommandContext.VDOM
    return FortiOSCommandContext.UNSPECIFIED


def _execution_support(
    path: str,
) -> tuple[FortiOSExecutionSupport, FortiOSParserSupport]:
    value = _STRUCTURED_COMMANDS.get(path.lower())
    if value is None:
        return FortiOSExecutionSupport.CATALOG_ONLY, FortiOSParserSupport.NONE
    return FortiOSExecutionSupport.STRUCTURED, value[1]


def _nearby_description(lines: list[str], line_number: int) -> str | None:
    for offset in (-1, 1, -2, 2, -3, 3):
        index = line_number - 1 + offset
        if index < 0 or index >= len(lines):
            continue
        value = lines[index].strip()
        if not value or value.startswith("|"):
            continue
        compact = re.sub(r"[^a-z]", "", value.lower())
        if compact.startswith(("fortios", "fortinet", "clidiagnose", "cliexecute")):
            continue
        if value.split(maxsplit=1)[0].lower() in _ALL_VERBS:
            continue
        if value.startswith("l ") or "Thistopicincludesthefollowingcommands" in value:
            continue
        return value[:2000]
    return None


def _coverage(
    definitions: list[FortiOSCommandDefinition],
    *,
    topic_count: int,
    syntax_count: int,
    artifact_count: int,
) -> FortiOSCatalogCoverage:
    classes = Counter(definition.command_class for definition in definitions)
    structured = sum(
        definition.execution_support is FortiOSExecutionSupport.STRUCTURED
        for definition in definitions
    )
    return FortiOSCatalogCoverage(
        source_topic_commands=topic_count,
        source_syntax_commands=syntax_count,
        source_context_commands=len(definitions) - topic_count - syntax_count,
        source_non_command_artifacts=artifact_count,
        commands_discovered=len(definitions),
        commands_catalogued=len(definitions),
        source_definitions_uncatalogued=0,
        read_only=classes[OperationClass.READ_ONLY],
        diagnostic=classes[OperationClass.DIAGNOSTIC],
        configuration=classes[OperationClass.CONFIGURATION],
        destructive=classes[OperationClass.DESTRUCTIVE],
        structured_executable=structured,
        executable_in_observe=sum(definition.executable_in_observe for definition in definitions),
        typed_parsers=sum(
            definition.parser_support is FortiOSParserSupport.TYPED for definition in definitions
        ),
        sanitized_text_parsers=sum(
            definition.parser_support is FortiOSParserSupport.SANITIZED_TEXT
            for definition in definitions
        ),
        catalog_only=len(definitions) - structured,
    )
