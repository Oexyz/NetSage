"""Bounded reviewed command variants for firmware-aware semantic collection."""

from dataclasses import dataclass
from enum import StrEnum

from netsage.drivers.fortios.commands import FortiOSCommand, FortiOSRequest
from netsage.drivers.fortios.semantic import (
    FortiOSSemanticErrorCategory,
    FortiOSSemanticParseError,
)
from netsage.drivers.fortios.version import FortiOSVersion

MAX_VARIANTS_PER_OPERATION = 3


class FortiOSVariantOperation(StrEnum):
    BGP_STATUS = "get_bgp_status"
    OSPF_STATUS = "get_ospf_status"


class FortiOSVariantFailure(StrEnum):
    COMMAND_UNAVAILABLE = "command_unavailable"
    EMPTY_OUTPUT = "empty_output"
    OUTPUT_UNRECOGNIZED = "output_unrecognized"


@dataclass(frozen=True, slots=True)
class SemanticCommandVariant:
    operation: FortiOSVariantOperation
    variant_id: str
    requests: tuple[FortiOSRequest, ...]
    parser_variant: str
    minimum_version: FortiOSVersion | None = None
    maximum_version: FortiOSVersion | None = None
    fallback_on: frozenset[FortiOSVariantFailure] = frozenset()
    source_reference: str = "fortinet-reviewed"

    def supports(self, version: FortiOSVersion) -> bool:
        return version.matches(minimum=self.minimum_version, maximum=self.maximum_version)


class FortiOSVariantExhaustedError(FortiOSSemanticParseError):
    def __init__(
        self,
        category: FortiOSSemanticErrorCategory,
        attempted_variants: tuple[str, ...],
    ) -> None:
        super().__init__(category, "Reviewed FortiOS semantic variants were exhausted")
        self.attempted_variants = attempted_variants


class FortiOSVariantRegistry:
    """Return at most three fixed variants; never synthesize a command."""

    def __init__(self) -> None:
        minimum = FortiOSVersion.parse("7.0.0")
        maximum = FortiOSVersion.parse("7.6.99")
        retryable = frozenset(
            {
                FortiOSVariantFailure.COMMAND_UNAVAILABLE,
                FortiOSVariantFailure.EMPTY_OUTPUT,
                FortiOSVariantFailure.OUTPUT_UNRECOGNIZED,
            }
        )
        self._variants = (
            SemanticCommandVariant(
                operation=FortiOSVariantOperation.BGP_STATUS,
                variant_id="bgp-summary-v1",
                requests=(FortiOSRequest(FortiOSCommand.BGP_SUMMARY),),
                parser_variant="bgp-summary-v1",
                minimum_version=minimum,
                maximum_version=maximum,
                fallback_on=retryable,
                source_reference="fortinet-bgp-summary",
            ),
            SemanticCommandVariant(
                operation=FortiOSVariantOperation.BGP_STATUS,
                variant_id="bgp-neighbors-v1",
                requests=(FortiOSRequest(FortiOSCommand.BGP_NEIGHBORS),),
                parser_variant="bgp-neighbors-v1",
                minimum_version=minimum,
                maximum_version=maximum,
                source_reference="fortinet-bgp-neighbors",
            ),
            SemanticCommandVariant(
                operation=FortiOSVariantOperation.OSPF_STATUS,
                variant_id="ospf-neighbor-all-v1",
                requests=(
                    FortiOSRequest(FortiOSCommand.OSPF_STATUS),
                    FortiOSRequest(FortiOSCommand.OSPF_NEIGHBORS),
                ),
                parser_variant="ospf-neighbor-all-v1",
                minimum_version=minimum,
                maximum_version=maximum,
                fallback_on=retryable,
                source_reference="fortinet-ospf-neighbor-all",
            ),
            SemanticCommandVariant(
                operation=FortiOSVariantOperation.OSPF_STATUS,
                variant_id="ospf-neighbor-v1",
                requests=(
                    FortiOSRequest(FortiOSCommand.OSPF_STATUS),
                    FortiOSRequest(FortiOSCommand.OSPF_NEIGHBORS_LEGACY),
                ),
                parser_variant="ospf-neighbor-v1",
                minimum_version=minimum,
                maximum_version=maximum,
                source_reference="fortinet-ospf-neighbor",
            ),
        )

    def candidates(
        self,
        operation: FortiOSVariantOperation,
        version: FortiOSVersion,
    ) -> tuple[SemanticCommandVariant, ...]:
        matches = tuple(
            variant
            for variant in self._variants
            if variant.operation is operation and variant.supports(version)
        )
        if len(matches) > MAX_VARIANTS_PER_OPERATION:
            raise RuntimeError("FortiOS semantic variant count exceeds the safety limit")
        return matches


def variant_failure_from_parser(
    error: FortiOSSemanticParseError,
) -> FortiOSVariantFailure | None:
    return {
        FortiOSSemanticErrorCategory.COMMAND_UNAVAILABLE: (
            FortiOSVariantFailure.COMMAND_UNAVAILABLE
        ),
        FortiOSSemanticErrorCategory.EMPTY_OUTPUT: FortiOSVariantFailure.EMPTY_OUTPUT,
        FortiOSSemanticErrorCategory.OUTPUT_UNRECOGNIZED: (
            FortiOSVariantFailure.OUTPUT_UNRECOGNIZED
        ),
    }.get(error.category)
