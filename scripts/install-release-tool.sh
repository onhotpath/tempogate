#!/usr/bin/env bash
# Installs one binary from a release tar.gz after verifying the archive's
# SHA-256, so prebuilt dev tools are pinned by digest like every other build
# input. Called by the Makefile; tool versions and checksums live in tools.mk.
#
# Usage: install-release-tool.sh <dest> <url> <sha256> <path-in-archive>
set -euo pipefail

dest=$1 url=$2 want=$3 member=$4

if [ -z "$want" ]; then
  echo "install-release-tool: no pinned SHA-256 for $(uname -s)/$(uname -m) ($url); add one to tools.mk" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

curl -fsSL --retry 3 -o "$tmp/archive.tar.gz" "$url"
if command -v sha256sum >/dev/null; then
  got=$(sha256sum "$tmp/archive.tar.gz" | cut -d' ' -f1)
else
  got=$(shasum -a 256 "$tmp/archive.tar.gz" | cut -d' ' -f1)
fi
if [ "$got" != "$want" ]; then
  echo "install-release-tool: checksum mismatch for $url" >&2
  echo "  want $want" >&2
  echo "  got  $got" >&2
  exit 1
fi

tar -xzf "$tmp/archive.tar.gz" -C "$tmp" "$member"
mkdir -p "$(dirname "$dest")"
install -m 0755 "$tmp/$member" "$dest"
