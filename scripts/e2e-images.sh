#!/usr/bin/env bash
# Prints the third-party images the e2e tests run: the default of every
# imageOr("E2E_..._IMAGE", "<image>") in test/e2e, one per line. Used by
# `make test-e2e-pull` (CI pre-pulls them) and scripts/check-pins.sh (each
# must be pinned by digest).
set -euo pipefail

cd "$(dirname "$0")/.."
grep -ohE 'imageOr\("[A-Z0-9_]+", "[^"]+"\)' test/e2e/*.go \
  | sed -E 's/^imageOr\("[A-Z0-9_]+", "([^"]+)"\)$/\1/' \
  | sort -u
