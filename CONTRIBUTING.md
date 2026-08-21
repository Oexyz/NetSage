# Contributing to NetSage

NetSage welcomes focused, security-conscious contributions. Install Python 3.13 and `uv`, then run:

```powershell
uv sync --dev
uv run pre-commit install
uv run ruff format .
uv run ruff check .
uv run mypy src
uv run python scripts/generate_fortios_catalog.py --check
uv run pytest
```

Never commit credentials or real device output containing sensitive data. New device operations must be structured, read-only, tested, and routed through the Tool Broker.

## Standalone binaries

Build the native executable on the target operating system:

```powershell
.\scripts\build-binary.ps1
```

```bash
sh scripts/build-binary.sh
```

PyInstaller does not cross-compile: Windows and each Linux architecture are
built and smoke-tested on their corresponding GitHub Actions runner.
