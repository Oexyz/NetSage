$ErrorActionPreference = 'Stop'

$architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($architecture -ne 'x64') {
    throw "Unsupported Windows release architecture: $architecture"
}

uv sync --locked --dev
uv run python scripts/package_binary.py 'netsage-windows-x64.exe'
