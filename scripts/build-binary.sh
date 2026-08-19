#!/bin/sh
set -eu

case "$(uname -m)" in
  x86_64|amd64) asset='netsage-linux-x64' ;;
  aarch64|arm64) asset='netsage-linux-arm64' ;;
  *) echo "Unsupported Linux release architecture: $(uname -m)" >&2; exit 1 ;;
esac

uv sync --locked --dev
uv run python scripts/package_binary.py "$asset"
