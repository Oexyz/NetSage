"""Generate or verify the FortiOS 7.2.13 command catalog from fortios.md."""

from __future__ import annotations

import argparse
import gzip
from pathlib import Path

from netsage.drivers.fortios.catalog.models import FortiOSCommandManifest
from netsage.drivers.fortios.catalog.source import (
    build_manifest,
    compressed_manifest_bytes,
    coverage_markdown,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    source = root / "fortios.md"
    manifest_path = (
        root
        / "src"
        / "netsage"
        / "drivers"
        / "fortios"
        / "catalog"
        / "generated"
        / "fortios_7_2_13.json.gz"
    )
    coverage_path = root / "docs" / "fortios-command-coverage.md"
    if not source.is_file():
        if not arguments.check:
            raise SystemExit("fortios.md is required to generate the FortiOS catalog")
        if not manifest_path.is_file():
            raise SystemExit("FortiOS generated manifest is missing")
        try:
            manifest = FortiOSCommandManifest.model_validate_json(
                gzip.decompress(manifest_path.read_bytes())
            )
        except (OSError, EOFError, ValueError) as error:
            raise SystemExit("FortiOS generated manifest is invalid") from error
        expected_coverage = coverage_markdown(manifest).encode("utf-8")
        if not coverage_path.is_file() or coverage_path.read_bytes() != expected_coverage:
            raise SystemExit("FortiOS command coverage document is stale")
        print(
            "FortiOS generated catalog is internally valid; local fortios.md source is not present"
        )
        return 0
    manifest = build_manifest(source)
    expected_manifest = compressed_manifest_bytes(manifest)
    expected_coverage = coverage_markdown(manifest).encode("utf-8")
    if arguments.check:
        if not manifest_path.is_file() or manifest_path.read_bytes() != expected_manifest:
            raise SystemExit("FortiOS generated manifest is stale")
        if not coverage_path.is_file() or coverage_path.read_bytes() != expected_coverage:
            raise SystemExit("FortiOS command coverage document is stale")
        print(f"FortiOS catalog is current: {manifest.coverage.commands_catalogued} commands")
        return 0
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_bytes(expected_manifest)
    coverage_path.write_bytes(expected_coverage)
    print(f"Generated {manifest_path}")
    print(f"Generated {coverage_path}")
    print(f"Commands catalogued: {manifest.coverage.commands_catalogued}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
