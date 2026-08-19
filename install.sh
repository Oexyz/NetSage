#!/bin/sh
set -eu

repository="${NETSAGE_REPOSITORY:-Oexyz/NetSage}"
version="${NETSAGE_VERSION:-latest}"
install_dir="${NETSAGE_INSTALL_DIR:-${HOME}/.local/bin}"

usage() {
  cat <<'EOF'
Install the latest NetSage Linux binary for the current user.

Usage: install.sh [--help]

Environment variables:
  NETSAGE_VERSION       Release tag to install (default: latest)
  NETSAGE_INSTALL_DIR   Destination directory (default: ~/.local/bin)
  NETSAGE_REPOSITORY    GitHub owner/repository (default: Oexyz/NetSage)
  NETSAGE_DOWNLOAD_BASE Testing or mirror override for the release directory URL
EOF
}

if [ "${1:-}" = "--help" ]; then
  usage
  exit 0
fi
if [ "$#" -ne 0 ]; then
  usage >&2
  exit 64
fi

for command in curl sha256sum mktemp install mv; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

case "$(uname -m)" in
  x86_64|amd64) asset="netsage-linux-x64" ;;
  aarch64|arm64) asset="netsage-linux-arm64" ;;
  *) echo "Unsupported Linux architecture: $(uname -m)" >&2; exit 1 ;;
esac

if [ -n "${NETSAGE_DOWNLOAD_BASE:-}" ]; then
  base_url="${NETSAGE_DOWNLOAD_BASE%/}"
elif [ "$version" = "latest" ]; then
  base_url="https://github.com/${repository}/releases/latest/download"
else
  case "$version" in
    *[!A-Za-z0-9._-]*) echo "Invalid NETSAGE_VERSION" >&2; exit 64 ;;
  esac
  base_url="https://github.com/${repository}/releases/download/${version}"
fi

temporary_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary_dir"
}
trap cleanup EXIT HUP INT TERM

fetch() {
  source_url="$1"
  destination="$2"
  case "$source_url" in
    https://*)
      curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 \
        "$source_url" --output "$destination"
      ;;
    file://*)
      if [ -z "${NETSAGE_DOWNLOAD_BASE:-}" ]; then
        echo "Refusing non-HTTPS download URL" >&2
        exit 1
      fi
      curl --fail --silent --show-error --location "$source_url" --output "$destination"
      ;;
    *) echo "Refusing non-HTTPS download URL" >&2; exit 1 ;;
  esac
}

fetch "${base_url}/SHA256SUMS" "${temporary_dir}/SHA256SUMS"
fetch "${base_url}/${asset}" "${temporary_dir}/${asset}"

expected="$(awk -v name="$asset" '$2 == name || $2 == "*" name { print $1; exit }' "${temporary_dir}/SHA256SUMS")"
case "$expected" in
  ''|*[!0-9A-Fa-f]*) echo "No valid checksum found for ${asset}" >&2; exit 1 ;;
esac
if [ "${#expected}" -ne 64 ]; then
  echo "Invalid checksum length for ${asset}" >&2
  exit 1
fi
actual="$(sha256sum "${temporary_dir}/${asset}" | awk '{print $1}')"
if [ "$actual" != "$expected" ]; then
  echo "Checksum verification failed for ${asset}" >&2
  exit 1
fi

install -d -m 0755 "$install_dir"
staged="${install_dir}/.netsage.new.$$"
install -m 0755 "${temporary_dir}/${asset}" "$staged"
mv -f "$staged" "${install_dir}/netsage"

echo "Installed NetSage to ${install_dir}/netsage"
case ":${PATH}:" in
  *":${install_dir}:"*) ;;
  *) echo "Add ${install_dir} to PATH, then open a new shell." ;;
esac
