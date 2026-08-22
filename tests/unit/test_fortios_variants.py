from collections.abc import Sequence
from pathlib import Path

import pytest

from netsage.drivers.fortios import (
    FortiOSCommand,
    FortiOSCommandTimeoutError,
    FortiOSCommandUnavailableError,
    FortiOSDriver,
    FortiOSPermissionDeniedError,
    FortiOSRequest,
    FortiOSSemanticRequest,
    FortiOSVariantExhaustedError,
    FortiOSVariantOperation,
    FortiOSVariantRegistry,
    FortiOSVersion,
)
from netsage.models import BGPSessionState, OSPFNeighborState

FIXTURES = Path(__file__).parents[1] / "fixtures" / "fortigate"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class VariantTransport:
    def __init__(self, outputs: dict[FortiOSCommand, str | Exception]) -> None:
        self.outputs = outputs
        self.commands: list[FortiOSCommand] = []

    async def execute(self, requests: Sequence[FortiOSRequest]) -> tuple[str, ...]:
        results = []
        for request in requests:
            self.commands.append(request.command)
            value = self.outputs[request.command]
            if isinstance(value, Exception):
                raise value
            results.append(value)
        return tuple(results)

    async def execute_semantic(
        self, _requests: Sequence[FortiOSRequest | FortiOSSemanticRequest]
    ) -> tuple[str, ...]:
        raise AssertionError("semantic catalog execution was not expected")


def facts(version: str = "7.2.13") -> str:
    return f"Version: FortiGate-VM64 v{version},build1762,260128\nHostname: fortigate-lab"


def test_fortios_version_is_typed_and_compares_numerically() -> None:
    current = FortiOSVersion.parse("7.10.2", build=2000, branch_point=1999, release="GA")
    unknown_patch = FortiOSVersion.parse("7.4.x")

    assert current.display == "7.10.2"
    assert current.matches(minimum=FortiOSVersion.parse("7.2.13")) is True
    assert current.matches(maximum=FortiOSVersion.parse("7.6.99")) is False
    assert unknown_patch.display == "7.4.x"
    assert unknown_patch.matches(minimum=FortiOSVersion.parse("7.0.0")) is False
    with pytest.raises(ValueError):
        FortiOSVersion.parse("7.x")


def test_variant_registry_is_bounded_and_version_aware() -> None:
    registry = FortiOSVariantRegistry()

    assert (
        len(
            registry.candidates(
                FortiOSVariantOperation.BGP_STATUS,
                FortiOSVersion.parse("7.2.13"),
            )
        )
        == 2
    )
    assert (
        len(
            registry.candidates(
                FortiOSVariantOperation.OSPF_STATUS,
                FortiOSVersion.parse("7.6.5"),
            )
        )
        == 2
    )
    assert (
        registry.candidates(
            FortiOSVariantOperation.BGP_STATUS,
            FortiOSVersion.parse("8.0.0"),
        )
        == ()
    )
    assert (
        registry.candidates(
            FortiOSVariantOperation.BGP_STATUS,
            FortiOSVersion.parse("6.4.16"),
        )
        == ()
    )


@pytest.mark.asyncio
async def test_bgp_falls_back_from_empty_summary_to_reviewed_detailed_variant() -> None:
    transport = VariantTransport(
        {
            FortiOSCommand.SYSTEM_STATUS: facts(),
            FortiOSCommand.BGP_SUMMARY: "",
            FortiOSCommand.BGP_NEIGHBORS: fixture("bgp_neighbors_detail.txt"),
        }
    )
    status = await FortiOSDriver("fortigate-lab", transport).get_bgp_status()

    assert status.parser.variant == "bgp-neighbors-v1"
    assert status.parser.attempted_variants == (
        "bgp-summary-v1",
        "bgp-neighbors-v1",
    )
    assert status.neighbors[0].state is BGPSessionState.ESTABLISHED
    assert status.neighbors[0].prefixes_advertised == 8
    assert status.neighbors[1].state is BGPSessionState.OPEN_CONFIRM


@pytest.mark.asyncio
async def test_bgp_command_unavailable_falls_back_but_permission_and_timeout_do_not() -> None:
    available = VariantTransport(
        {
            FortiOSCommand.SYSTEM_STATUS: facts(),
            FortiOSCommand.BGP_SUMMARY: FortiOSCommandUnavailableError("unavailable"),
            FortiOSCommand.BGP_NEIGHBORS: fixture("bgp_neighbors_detail.txt"),
        }
    )
    assert (
        await FortiOSDriver("fortigate-lab", available).get_bgp_status()
    ).parser.variant == "bgp-neighbors-v1"

    for error in (
        FortiOSPermissionDeniedError("denied"),
        FortiOSCommandTimeoutError("timeout"),
    ):
        blocked = VariantTransport(
            {
                FortiOSCommand.SYSTEM_STATUS: facts(),
                FortiOSCommand.BGP_SUMMARY: error,
                FortiOSCommand.BGP_NEIGHBORS: fixture("bgp_neighbors_detail.txt"),
            }
        )
        with pytest.raises(type(error)):
            await FortiOSDriver("fortigate-lab", blocked).get_bgp_status()
        assert FortiOSCommand.BGP_NEIGHBORS not in blocked.commands


@pytest.mark.asyncio
async def test_ospf_uses_legacy_reviewed_variant_only_after_controlled_failure() -> None:
    transport = VariantTransport(
        {
            FortiOSCommand.SYSTEM_STATUS: facts(),
            FortiOSCommand.OSPF_STATUS: fixture("ospf_status.txt"),
            FortiOSCommand.OSPF_NEIGHBORS: FortiOSCommandUnavailableError("unavailable"),
            FortiOSCommand.OSPF_NEIGHBORS_LEGACY: fixture("ospf_neighbors_vrf.txt"),
        }
    )
    status = await FortiOSDriver("fortigate-lab", transport).get_ospf_status()

    assert status.parser.variant == "ospf-neighbor-v1"
    assert status.parser.attempted_variants == (
        "ospf-neighbor-all-v1",
        "ospf-neighbor-v1",
    )
    assert status.neighbors[0].state is OSPFNeighborState.TWO_WAY
    assert status.neighbors[1].state is OSPFNeighborState.EXSTART
    assert "tun-id" in (status.neighbors[1].interface or "")


@pytest.mark.asyncio
async def test_unreviewed_future_firmware_fails_without_random_commands() -> None:
    transport = VariantTransport({FortiOSCommand.SYSTEM_STATUS: facts("8.0.0")})

    with pytest.raises(FortiOSVariantExhaustedError) as captured:
        await FortiOSDriver("fortigate-lab", transport).get_bgp_status()

    assert captured.value.attempted_variants == ()
    assert transport.commands == [FortiOSCommand.SYSTEM_STATUS]
