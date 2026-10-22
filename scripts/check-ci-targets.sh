#!/usr/bin/env bash
# Fails if the CI workflow stops running exactly what `make ci` runs.
#
# `make ci` is the single local entry point and the definition of CI. The
# workflow splits its prerequisites across parallel jobs: each job declares
# its share in a `CI_TARGETS:` env entry and runs `make ${{ env.CI_TARGETS }}`. This
# asserts that the union of those shares equals `ci`'s prerequisites (no
# target dropped, none added) and that no target is run twice.
set -euo pipefail

cd "$(dirname "$0")/.."
workflow=.github/workflows/ci.yml

# -q exits non-zero when ci is out of date, which it always is (phony).
want=$({ make -pRrq ci 2>/dev/null || true; } | awk '/^ci:/ && !seen++ { sub(/^ci:/, ""); print }' | tr -s ' ' '\n' | sed '/^$/d' | sort)
if [ -z "$want" ]; then
  echo "check-ci-targets: could not read the prerequisites of 'make ci'" >&2
  exit 1
fi

got=$(sed -nE 's/^[[:space:]]*CI_TARGETS:[[:space:]]*//p' "$workflow" | tr -d "\"'" | tr -s ' ' '\n' | sed '/^$/d' | sort)
defs=$(grep -cE '^[[:space:]]*CI_TARGETS:' "$workflow" || true)
runs=$(grep -cE '^[[:space:]]*run: make \$\{\{ env\.CI_TARGETS \}\}$' "$workflow" || true)

status=0
if [ "$defs" -eq 0 ] || [ "$defs" != "$runs" ]; then
  echo "check-ci-targets: $workflow has $defs CI_TARGETS entries but $runs 'run: make \${{ env.CI_TARGETS }}' steps; each job that declares CI_TARGETS must run it" >&2
  status=1
fi
dups=$(printf '%s\n' "$got" | uniq -d)
if [ -n "$dups" ]; then
  echo "check-ci-targets: targets run by more than one CI job: $(echo $dups)" >&2
  status=1
fi
if [ "$(printf '%s\n' "$want")" != "$(printf '%s\n' "$got" | uniq)" ]; then
  echo "check-ci-targets: CI jobs run a different set of targets than 'make ci':" >&2
  echo "  make ci:   $(echo $want)" >&2
  echo "  workflow:  $(echo $got)" >&2
  status=1
fi
exit $status
