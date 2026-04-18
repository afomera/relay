#!/usr/bin/env sh
# relay CLI installer.
#
#   curl -fsSL https://raw.githubusercontent.com/afomera/relay/main/scripts/install.sh | sh
#
# Respects:
#   VERSION=v0.2.0     pin a specific release
#   PREFIX=/opt/bin    where to install (default: /usr/local/bin)
#   REPO=owner/repo    fork override

set -eu

REPO="${REPO:-afomera/relay}"
VERSION="${VERSION:-latest}"
PREFIX="${PREFIX:-/usr/local/bin}"

OS="$(uname -s)"
ARCH="$(uname -m)"

# v1: Apple Silicon only. Intel macOS + Linux targets land when we expand
# the release matrix.
if [ "$OS" != "Darwin" ] || ! { [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; }; then
    cat >&2 <<EOF
relay v1 releases target Apple Silicon macOS only. Detected: $OS/$ARCH.

If you're on a supported platform that doesn't have a release yet, build
from source:

    git clone https://github.com/${REPO}
    cd relay && cargo build --release --bin relay
    install -m 0755 target/release/relay /usr/local/bin/relay

Or install via cargo:

    cargo install --git https://github.com/${REPO} relay-cli
EOF
    exit 1
fi

TARGET="aarch64-apple-darwin"

if [ "$VERSION" = "latest" ]; then
    VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
    if [ -z "$VERSION" ]; then
        echo "couldn't resolve latest version for ${REPO}" >&2
        exit 1
    fi
fi

ASSET="relay-${VERSION}-${TARGET}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${VERSION}/${ASSET}"

printf 'fetching %s\n' "$URL"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

if ! curl -fsSL "$URL" | tar xz -C "$TMP"; then
    echo "download or extract failed" >&2
    exit 1
fi

if [ ! -x "$TMP/relay" ]; then
    echo "archive did not contain a 'relay' binary" >&2
    exit 1
fi

# sudo only when we need it.
dest="$PREFIX/relay"
if [ -w "$(dirname "$dest")" ]; then
    install -m 0755 "$TMP/relay" "$dest"
else
    sudo install -m 0755 "$TMP/relay" "$dest"
fi

printf '\ninstalled %s\n' "$dest"
"$dest" --version || true
printf '\n  $ relay auth login --token <your-token>\n  $ relay http 3000\n\n'
