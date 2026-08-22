"""Parse FortiOS HA checksum comparison output without retaining fingerprints."""

import re
from collections import defaultdict

from netsage.drivers.fortios.semantic.common import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
    require_recognizable_output,
)
from netsage.models import (
    HAChecksumMismatch,
    HAChecksumScope,
    HAChecksumScopeResult,
    HAChecksumStatus,
    SemanticParserMetadata,
    SemanticParserState,
)
from netsage.models.ha_diagnostics import MAX_HA_CHECKSUM_SCOPES

MAX_HA_CHECKSUM_SOURCE_CHARACTERS = 131_072
MAX_HA_CHECKSUM_SOURCE_LINES = 512

_SCOPED_DIGEST = re.compile(
    r"^\s*(?P<label>[^:\r\n]{1,80})\s*:\s*"
    r"(?P<digest>(?:(?:[0-9A-Fa-f]{2}\s+){7,}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{16,128}))"
    r"\s*$"
)
_SAFE_HEADER = re.compile(
    r"(?i)^(?:checksum|[A-Za-z0-9_.-]{1,80}|"
    r"is_[a-z_]+\(\)=\d+(?:\s*,\s*is_[a-z_]+\(\)=\d+)*)$"
)


def parse_ha_checksum_nonsync(
    device_id: str,
    output: str,
    *,
    variant: str = "ha-checksum-nonsync-v1",
) -> HAChecksumStatus:
    source = require_recognizable_output(output, "HA checksum non-sync")
    source_truncated = len(source) > MAX_HA_CHECKSUM_SOURCE_CHARACTERS
    text = source[:MAX_HA_CHECKSUM_SOURCE_CHARACTERS]
    if source_truncated and "\n" in text:
        text = text.rsplit("\n", 1)[0]

    all_lines = tuple(line for line in text.splitlines() if line.strip())
    line_truncated = len(all_lines) > MAX_HA_CHECKSUM_SOURCE_LINES
    lines = all_lines[:MAX_HA_CHECKSUM_SOURCE_LINES]
    values: dict[HAChecksumScope, list[str]] = defaultdict(list)
    unrecognized = 0
    for line in lines:
        match = _SCOPED_DIGEST.match(line)
        if match is None:
            if not _SAFE_HEADER.fullmatch(line.strip()):
                unrecognized += 1
            continue
        scope = _scope(match.group("label"))
        digest = re.sub(r"\s+", "", match.group("digest")).casefold()
        values[scope].append(digest)

    if not values:
        raise FortiOSSemanticParseError(
            FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED,
            "FortiOS HA checksum non-sync output was not recognized",
        )

    scope_results: list[HAChecksumScopeResult] = []
    mismatches: list[HAChecksumMismatch] = []
    for scope in sorted(values, key=lambda item: item.value):
        compared = len(values[scope])
        distinct = len(set(values[scope]))
        synchronized = None if compared < 2 else distinct == 1
        scope_results.append(
            HAChecksumScopeResult(
                scope=scope,
                compared_values=compared,
                distinct_values=distinct,
                synchronized=synchronized,
            )
        )
        if synchronized is False:
            mismatches.append(
                HAChecksumMismatch(
                    scope=scope,
                    category=scope.value,
                    compared_values=compared,
                    distinct_values=distinct,
                )
            )

    model_truncated = len(scope_results) > MAX_HA_CHECKSUM_SCOPES
    bounded_scopes = tuple(scope_results[:MAX_HA_CHECKSUM_SCOPES])
    bounded_mismatches = tuple(mismatches[:MAX_HA_CHECKSUM_SCOPES])
    comparable = tuple(item for item in bounded_scopes if item.synchronized is not None)
    synchronized = (
        None if not comparable else not any(item.synchronized is False for item in comparable)
    )
    truncated = source_truncated or line_truncated or model_truncated
    state = SemanticParserState.PARTIAL if truncated or unrecognized else SemanticParserState.PARSED
    return HAChecksumStatus(
        device_id=device_id,
        parser=SemanticParserMetadata(
            state=state,
            variant=variant,
            attempted_variants=(variant,),
        ),
        synchronized=synchronized,
        scopes=bounded_scopes,
        mismatches=bounded_mismatches,
        mismatch_count=len(bounded_mismatches),
        source_line_count=len(lines),
        truncated=truncated,
    )


def _scope(label: str) -> HAChecksumScope:
    normalized = label.strip().casefold()
    if normalized == "global":
        return HAChecksumScope.GLOBAL
    if normalized == "all":
        return HAChecksumScope.ALL
    if normalized:
        # VDOM names are intentionally collapsed instead of being persisted.
        return HAChecksumScope.VDOM
    return HAChecksumScope.UNKNOWN
