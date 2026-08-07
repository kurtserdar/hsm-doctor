#!/bin/sh
# Installs the latest hsmdoctor release binary for this OS/architecture.
#
#   curl -fsSL https://raw.githubusercontent.com/kurtserdar/hsm-doctor/main/install.sh | sh
#
# Installs to /usr/local/bin (using sudo if needed). Override the location with
# PREFIX, e.g. no-sudo install into your home directory:
#
#   curl -fsSL .../install.sh | PREFIX="$HOME/.local/bin" sh
set -eu

REPO="kurtserdar/hsm-doctor"
PREFIX="${PREFIX:-/usr/local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  linux | darwin) ;;
  *) echo "hsmdoctor: unsupported OS '$os' (use the Docker image or build from source)" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64 | amd64) arch="amd64" ;;
  aarch64 | arm64) arch="arm64" ;;
  *) echo "hsmdoctor: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

echo "hsmdoctor: finding the latest release..."
ver=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
  | grep '"tag_name"' | head -1 | sed -E 's/.*"v?([^"]+)".*/\1/')
[ -n "$ver" ] || { echo "hsmdoctor: could not determine the latest version" >&2; exit 1; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
name="hsmdoctor_${ver}_${os}_${arch}"
url="https://github.com/${REPO}/releases/download/v${ver}/${name}.tar.gz"

echo "hsmdoctor: downloading ${ver} for ${os}/${arch}..."
curl -fsSL "$url" -o "$tmp/hsmdoctor.tar.gz"
tar xzf "$tmp/hsmdoctor.tar.gz" -C "$tmp"
bin="$tmp/${name}/hsmdoctor"

if [ -w "$PREFIX" ]; then
  install -m 0755 "$bin" "$PREFIX/hsmdoctor"
elif command -v sudo >/dev/null 2>&1; then
  echo "hsmdoctor: installing to ${PREFIX} (sudo)..."
  sudo install -m 0755 "$bin" "$PREFIX/hsmdoctor"
else
  echo "hsmdoctor: cannot write to ${PREFIX} and sudo is unavailable." >&2
  echo "           re-run with PREFIX set, e.g. PREFIX=\$HOME/.local/bin" >&2
  exit 1
fi

echo "hsmdoctor: installed to ${PREFIX}/hsmdoctor"
"$PREFIX/hsmdoctor" version 2>/dev/null || true
