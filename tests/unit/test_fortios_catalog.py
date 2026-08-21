from pathlib import Path

import pytest

from netsage.drivers.fortios.catalog import (
    FortiOSCommandRegistry,
    FortiOSCommandRenderError,
    FortiOSExecutionSupport,
    FortiOSParserSupport,
    load_manifest,
)
from netsage.drivers.fortios.catalog.source import (
    build_manifest,
    compressed_manifest_bytes,
    coverage_markdown,
)
from netsage.policies import ObservePolicy, OperationClass

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "fortios.md"
GENERATED = (
    ROOT
    / "src"
    / "netsage"
    / "drivers"
    / "fortios"
    / "catalog"
    / "generated"
    / "fortios_7_2_13.json.gz"
)
COVERAGE_DOCUMENT = ROOT / "docs" / "fortios-command-coverage.md"


@pytest.fixture(scope="module")
def source_manifest():
    if not SOURCE.is_file():
        pytest.skip("local copyrighted fortios.md source is not present")
    return build_manifest(SOURCE)


def test_generated_catalog_exactly_matches_complete_source(source_manifest) -> None:
    assert GENERATED.read_bytes() == compressed_manifest_bytes(source_manifest)
    assert COVERAGE_DOCUMENT.read_text(encoding="utf-8") == coverage_markdown(source_manifest)
    assert source_manifest.source_bytes == SOURCE.stat().st_size
    assert source_manifest.source_lines == len(SOURCE.read_text(encoding="utf-8-sig").splitlines())
    coverage = source_manifest.coverage
    assert coverage.source_topic_commands == 4_972
    assert coverage.source_syntax_commands == 232
    assert coverage.source_context_commands == 13_826
    assert coverage.source_non_command_artifacts == 55
    assert coverage.commands_discovered == 19_030
    assert coverage.commands_catalogued == coverage.commands_discovered


def test_runtime_manifest_has_unique_traceable_policy_aware_definitions() -> None:
    manifest = load_manifest()
    ids = [definition.id for definition in manifest.definitions]

    assert len(ids) == len(set(ids)) == manifest.coverage.commands_catalogued
    assert all(definition.source.document == "fortios.md" for definition in manifest.definitions)
    assert all(definition.source.line > 0 for definition in manifest.definitions)
    assert all(definition.source.page is not None for definition in manifest.definitions)
    assert {definition.command_class for definition in manifest.definitions} == set(OperationClass)
    assert COVERAGE_DOCUMENT.read_text(encoding="utf-8") == coverage_markdown(manifest)


def test_catalog_class_counts_and_execution_claims_are_exact() -> None:
    coverage = load_manifest().coverage

    assert coverage.source_topic_commands == 4_972
    assert coverage.source_syntax_commands == 232
    assert coverage.source_context_commands == 13_826
    assert coverage.source_non_command_artifacts == 55
    assert coverage.commands_discovered == coverage.commands_catalogued == 19_030
    assert coverage.source_definitions_uncatalogued == 0
    assert coverage.read_only == 1_049
    assert coverage.diagnostic == 2_758
    assert coverage.configuration == 14_390
    assert coverage.destructive == 833
    assert coverage.structured_executable == 2
    assert coverage.executable_in_observe == 0
    assert coverage.typed_parsers == 2
    assert coverage.sanitized_text_parsers == 0
    assert coverage.catalog_only == 19_028


def test_observe_policy_denies_catalogued_configuration_and_destructive_commands() -> None:
    registry = FortiOSCommandRegistry()
    policy = ObservePolicy()
    configuration = registry.get("fortios.config.system.interface")
    destructive = registry.get("fortios.execute.reboot")
    read_only = next(
        definition
        for definition in registry.manifest.definitions
        if definition.command_class is OperationClass.READ_ONLY
    )

    assert policy.authorize(configuration.id, configuration.command_class).allowed is False
    assert policy.authorize(destructive.id, destructive.command_class).allowed is False
    assert policy.authorize(read_only.id, read_only.command_class).allowed is True
    assert configuration.execution_support is FortiOSExecutionSupport.CATALOG_ONLY
    assert destructive.execution_support is FortiOSExecutionSupport.CATALOG_ONLY
    assert all(
        policy.authorize(definition.id, definition.command_class).allowed is False
        for definition in registry.manifest.definitions
        if definition.command_class in {OperationClass.CONFIGURATION, OperationClass.DESTRUCTIVE}
    )


def test_only_existing_typed_diagnostics_have_structured_execution() -> None:
    structured = {
        definition.id: definition
        for definition in load_manifest().definitions
        if definition.execution_support is FortiOSExecutionSupport.STRUCTURED
    }

    assert set(structured) == {"fortios.execute.ping", "fortios.execute.traceroute"}
    assert all(
        definition.command_class is OperationClass.DIAGNOSTIC
        and definition.parser_support is FortiOSParserSupport.TYPED
        and definition.observe_allowed is False
        for definition in structured.values()
    )


def test_semantic_classification_is_not_prefix_only() -> None:
    registry = FortiOSCommandRegistry()

    assert registry.get("fortios.config.system.interface").command_class is (
        OperationClass.CONFIGURATION
    )
    assert registry.get("fortios.execute.reboot").command_class is OperationClass.DESTRUCTIVE
    assert registry.get("fortios.diagnose.debug.flow.filter.clear").command_class is (
        OperationClass.DESTRUCTIVE
    )
    assert registry.get("fortios.execute.auto-script.result").command_class is (
        OperationClass.READ_ONLY
    )
    assert registry.get("fortios.execute.ping").command_class is OperationClass.DIAGNOSTIC


def test_typed_renderer_accepts_ip_and_rejects_injection() -> None:
    registry = FortiOSCommandRegistry()

    assert registry.render("fortios.execute.ping", {"ip": "192.0.2.1"}) == (
        "execute ping 192.0.2.1"
    )
    assert registry.render("fortios.execute.traceroute", {"dest": "2001:db8::1"}) == (
        "execute traceroute 2001:db8::1"
    )
    for value in (
        "192.0.2.1\nexecute reboot",
        "192.0.2.1;execute reboot",
        "$(execute reboot)",
        "192.0.2.1 | execute reboot",
    ):
        with pytest.raises(FortiOSCommandRenderError):
            registry.render("fortios.execute.ping", {"ip": value})


def test_sensitive_source_arguments_are_known_but_not_renderable() -> None:
    definitions = [
        definition
        for definition in load_manifest().definitions
        if any(argument.sensitive for argument in definition.arguments)
    ]

    assert definitions
    assert all(definition.renderable is False for definition in definitions)


def test_hyphenated_source_paths_remain_distinct() -> None:
    registry = FortiOSCommandRegistry()

    spaced = registry.get("fortios.diagnose.vpn.ike.log.filter")
    hyphenated = registry.get("fortios.diagnose.vpn.ike.log-filter")
    assert spaced.path != hyphenated.path
    assert spaced.source.line != hyphenated.source.line
