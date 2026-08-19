"""Build and name one native NetSage release binary."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

from PyInstaller.__main__ import run as run_pyinstaller


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("asset_name", help="Final GitHub Release asset filename")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    current_directory = Path.cwd()
    try:
        # PyInstaller resolves the spec file relative to the working directory.
        os.chdir(root)
        run_pyinstaller(["--clean", "--noconfirm", "netsage.spec"])
    finally:
        os.chdir(current_directory)
    built_name = "netsage.exe" if sys.platform == "win32" else "netsage"
    source = root / "dist" / built_name
    if not source.is_file():
        raise FileNotFoundError(f"PyInstaller output not found: {source}")

    output_dir = root / "artifacts"
    output_dir.mkdir(exist_ok=True)
    destination = output_dir / args.asset_name
    shutil.copy2(source, destination)
    if sys.platform != "win32":
        destination.chmod(destination.stat().st_mode | 0o111)
    print(destination)


if __name__ == "__main__":
    main()
