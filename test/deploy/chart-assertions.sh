#!/usr/bin/env bash
# Static checks on the rendered Helm chart: no cluster needed, only helm and
# yq (mikefarah v4). Every check runs; the script exits non-zero if any fail.
#
#   test/deploy/chart-assertions.sh      # or: make test-chart
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT/charts/tempogate"
RELEASE=tempogate

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need helm; need yq

failures=0
pass() { echo "ok   $1"; }
fail() { echo "FAIL $1" >&2; failures=$((failures + 1)); }

render() { helm template "$RELEASE" "$CHART" "$@" 2>&1; }

# expect_render_error DESC PATTERN HELM_ARGS...: the render must fail and the
# error must mention PATTERN.
expect_render_error() {
  local desc="$1" pattern="$2" out
  shift 2
  if out=$(render "$@"); then
    fail "$desc: render succeeded, want an error matching '$pattern'"
  elif ! grep -q -- "$pattern" <<<"$out"; then
    fail "$desc: error does not mention '$pattern': $out"
  else
    pass "$desc"
  fi
}

# expect_eq DESC WANT GOT
expect_eq() {
  if [ "$2" = "$3" ]; then pass "$1"; else fail "$1: want '$2', got '$3'"; fi
}

manifests=$(render) || { echo "FAIL default render: $manifests" >&2; exit 1; }
# q KIND EXPR: evaluate EXPR against the rendered object of KIND. Selecting
# first and evaluating in a second yq keeps collect ([...]) expressions from
# yielding an empty array for every other document.
q() { yq "select(.kind == \"$1\")" <<<"$manifests" | yq "$2"; }

echo "==> single-writer guard"
expect_render_error "replicaCount=2 is rejected" "replicaCount" --set replicaCount=2
expect_render_error "autoscaling.enabled=true is rejected" "autoscaling" --set autoscaling.enabled=true
expect_eq "replicaCount=0 still renders (scale to zero)" "0" \
  "$(render --set replicaCount=0 | yq 'select(.kind == "Deployment") | .spec.replicas')"
expect_eq "no HorizontalPodAutoscaler is rendered" "" "$(yq 'select(.kind == "HorizontalPodAutoscaler")' <<<"$manifests")"

echo "==> ServiceAccount token automount off"
expect_eq "ServiceAccount automountServiceAccountToken" "false" "$(q ServiceAccount .automountServiceAccountToken)"
expect_eq "Deployment pod automountServiceAccountToken" "false" \
  "$(q Deployment .spec.template.spec.automountServiceAccountToken)"

echo "==> seccompProfile RuntimeDefault"
expect_eq "Deployment pod seccompProfile" "RuntimeDefault" \
  "$(q Deployment .spec.template.spec.securityContext.seccompProfile.type)"
expect_eq "Deployment containers seccompProfile" "RuntimeDefault" \
  "$(q Deployment '[(.spec.template.spec.initContainers // [])[], .spec.template.spec.containers[] | .securityContext.seccompProfile.type] | unique | join(",")')"
expect_eq "test pod seccompProfile" "RuntimeDefault" \
  "$(q Pod .spec.securityContext.seccompProfile.type)"
expect_eq "test pod runs as non-root" "true" "$(q Pod .spec.securityContext.runAsNonRoot)"

echo "==> test-connection image pinned by digest"
image=$(q Pod '.spec.containers[0].image')
if [[ "$image" =~ ^[^@]+:[^@:]+@sha256:[0-9a-f]{64}$ ]]; then
  pass "test pod image is tag@digest ($image)"
else
  fail "test pod image is not pinned as repo:tag@sha256:<digest>: '$image'"
fi

if [ "$failures" -ne 0 ]; then
  echo "FAIL: $failures chart assertion(s) failed" >&2
  exit 1
fi
echo "PASS: chart assertions"
