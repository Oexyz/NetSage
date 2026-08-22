import json
from datetime import UTC, datetime
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from netsage.cli import fortios_compatibility_commands as compatibility_cli
from netsage.cli.main import app
from netsage.compatibility import (
    CapabilityObservationState,
    CompatibilityArea,
    CompatibilityAreaResult,
    CompatibilityErrorCategory,
    CompatibilityParserState,
    FortiOSCompatibilityReport,
    FortiOSVDOMContext,
    FortiOSVDOMMode,
    FortiOSVDOMProfile,
)
from netsage.drivers.fortios import FortiOSVersion
from netsage.models import Capability

runner = CliRunner()


def report(device_id: str = "firewall-example") -> FortiOSCompatibilityReport:
    capabilities = {
        CompatibilityArea.SYSTEM: (Capability.FACTS, Capability.SYSTEM_HEALTH),
        CompatibilityArea.INTERFACES: (Capability.INTERFACES,),
        CompatibilityArea.ROUTING: (Capability.ROUTES,),
        CompatibilityArea.FIREWALL: (Capability.FIREWALL,),
        CompatibilityArea.HA: (Capability.HA,),
        CompatibilityArea.SDWAN: (Capability.SDWAN,),
        CompatibilityArea.IPSEC: (Capability.IPSEC,),
        CompatibilityArea.BGP: (Capability.BGP,),
        CompatibilityArea.OSPF: (Capability.OSPF,),
    }
    operations = {
        CompatibilityArea.SYSTEM: ("get_device_facts", "get_system_health"),
        CompatibilityArea.INTERFACES: ("get_interfaces",),
        CompatibilityArea.ROUTING: ("get_route_summary",),
        CompatibilityArea.FIREWALL: ("get_firewall_policies",),
        CompatibilityArea.HA: ("get_ha_status",),
        CompatibilityArea.SDWAN: ("get_sdwan_status",),
        CompatibilityArea.IPSEC: ("get_ipsec_status",),
        CompatibilityArea.BGP: ("get_bgp_status",),
        CompatibilityArea.OSPF: ("get_ospf_status",),
    }
    return FortiOSCompatibilityReport(
        netsage_version="0.1.0.dev0",
        generated_at=datetime(2026, 8, 22, 12, 0, tzinfo=UTC),
        device_id=device_id,
        firmware=FortiOSVersion.parse("7.2.13", build=1762),
        model_family="FortiGate-80F",
        vdom=FortiOSVDOMProfile(
            mode=FortiOSVDOMMode.SINGLE,
            context=FortiOSVDOMContext.ROOT,
            maximum=10,
        ),
        areas=tuple(
            CompatibilityAreaResult(
                area=area,
                operations=operations[area],
                capabilities=capabilities[area],
                state=(
                    CapabilityObservationState.SUPPORTED
                    if area
                    in {
                        CompatibilityArea.SYSTEM,
                        CompatibilityArea.INTERFACES,
                        CompatibilityArea.ROUTING,
                        CompatibilityArea.FIREWALL,
                    }
                    else CapabilityObservationState.ENABLED
                ),
                parser_state=CompatibilityParserState.PARSED,
                parser_variants=(f"{area.value}-v1",),
                error_category=CompatibilityErrorCategory.NONE,
            )
            for area in CompatibilityArea
        ),
        fingerprint="a" * 64,
    )


class FakeService:
    calls: ClassVar[list[str]] = []

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def inspect(self, device_id: str) -> FortiOSCompatibilityReport:
        self.calls.append(device_id)
        return report(device_id)


@pytest.fixture(autouse=True)
def fake_service(monkeypatch: pytest.MonkeyPatch) -> None:
    FakeService.calls = []
    monkeypatch.setattr(compatibility_cli, "_state", object)
    monkeypatch.setattr(compatibility_cli, "FortiOSCompatibilityService", FakeService)


def test_compatibility_human_and_json_outputs_are_typed_and_safe() -> None:
    human = runner.invoke(app, ["fortios", "compatibility", "firewall-example"])
    structured = runner.invoke(
        app,
        ["fortios", "compatibility", "firewall-example", "--json"],
    )

    assert human.exit_code == 0
    assert "FortiOS Compatibility Report" in human.stdout
    assert "No raw CLI was stored" in human.stdout
    payload = json.loads(structured.stdout)
    assert payload["device_id"] == "fortios-device"
    assert payload["anonymized"] is True
    assert payload["firmware"]["major"] == 7
    assert payload["raw_cli_included"] is False
    assert "credential-reference-canary" not in structured.stdout
    assert payload["credentials_included"] is False


def test_compatibility_export_is_anonymized_and_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    first = runner.invoke(
        app,
        [
            "fortios",
            "compatibility",
            "credential-reference-canary",
            "--export",
            str(target),
        ],
    )
    second = runner.invoke(
        app,
        [
            "fortios",
            "compatibility",
            "credential-reference-canary",
            "--export",
            str(target),
        ],
    )
    forced = runner.invoke(
        app,
        [
            "fortios",
            "compatibility",
            "credential-reference-canary",
            "--export",
            str(target),
            "--force",
        ],
    )

    assert first.exit_code == 0
    assert second.exit_code == 1
    assert forced.exit_code == 0
    content = target.read_text(encoding="utf-8")
    assert "credential-reference-canary" not in content
    assert FortiOSCompatibilityReport.model_validate_json(content).anonymized is True

    combined_target = tmp_path / "combined.json"
    combined = runner.invoke(
        app,
        [
            "fortios",
            "compatibility",
            "firewall-example",
            "--json",
            "--export",
            str(combined_target),
        ],
    )
    assert combined.exit_code == 0
    assert json.loads(combined.stdout)["anonymized"] is True
    assert combined_target.exists()


def test_compatibility_one_shot_and_repl_use_the_same_handler() -> None:
    one_shot = runner.invoke(app, ["fortios", "compatibility", "firewall-example"])
    repl = runner.invoke(
        app,
        [],
        input="fortios compatibility firewall-example\nexit\n",
    )

    assert one_shot.exit_code == 0
    assert repl.exit_code == 0
    assert FakeService.calls == ["firewall-example", "firewall-example"]


def test_compatibility_help_does_not_prepare_a_runtime() -> None:
    result = runner.invoke(app, ["fortios", "compatibility", "--help"])

    assert result.exit_code == 0
    assert "--json" in result.stdout
    assert "--export" in result.stdout
    assert FakeService.calls == []
