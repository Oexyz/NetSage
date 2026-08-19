#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
temporary="$(mktemp -d)"
cleanup() {
  rm -rf -- "$temporary"
}
trap cleanup EXIT HUP INT TERM

case "$(uname -m)" in
  x86_64|amd64) asset='netsage-linux-x64' ;;
  aarch64|arm64) asset='netsage-linux-arm64' ;;
  *) echo 'Unsupported test architecture' >&2; exit 1 ;;
esac

printf '#!/bin/sh\necho NetSage-test\n' > "${temporary}/${asset}"
chmod 0755 "${temporary}/${asset}"
(
  cd "$temporary"
  sha256sum "$asset" > SHA256SUMS
)

case "$(uname -s)" in
  MINGW*|MSYS*) download_base="file:///$(cygpath -m "$temporary")" ;;
  *) download_base="file://${temporary}" ;;
esac

HOME="${temporary}/home" \
NETSAGE_DOWNLOAD_BASE="$download_base" \
NETSAGE_INSTALL_DIR="${temporary}/home/.local/bin" \
  sh "${root}/install.sh"

test -x "${temporary}/home/.local/bin/netsage"
output="$(${temporary}/home/.local/bin/netsage)"
test "$output" = 'NetSage-test'

printf 'tampered\n' >> "${temporary}/${asset}"
if HOME="${temporary}/home" \
  NETSAGE_DOWNLOAD_BASE="$download_base" \
  NETSAGE_INSTALL_DIR="${temporary}/home/.local/bin" \
  sh "${root}/install.sh" >/dev/null 2>&1; then
  echo 'installer accepted a tampered binary' >&2
  exit 1
fi
output="$(${temporary}/home/.local/bin/netsage)"
test "$output" = 'NetSage-test'

printf 'installer smoke test passed\n'
