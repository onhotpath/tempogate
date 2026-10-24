#!/usr/bin/env bash
# Lints the Helm chart and validates every rendered manifest against the
# Kubernetes OpenAPI schemas, for a set of value files that between them turn
# on every template. No cluster needed, only helm and kubeconform. Every
# combination runs; the script exits non-zero if any fail.
#
#   test/deploy/chart-lint.sh            # or: make lint-chart
#
# Env:
#   KUBE_VERSIONS  space-separated Kubernetes versions to validate against
#                  (default: the chart's minimum kubeVersion and the version
#                  of the kind node the smoke test installs into)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT/charts/tempogate"
RELEASE=tempogate
KUBE_VERSIONS="${KUBE_VERSIONS:-1.25.0 1.37.0}"

# The only CRD the chart renders is the Gateway API HTTPRoute. Its schema
# comes from the CRDs catalog, pinned to a commit so a catalog change cannot
# break or silently loosen this check.
CRDS_CATALOG=https://raw.githubusercontent.com/datreeio/CRDs-catalog/501527ab9c40c827144c8f45945b25a023e344ce

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need helm; need kubeconform

# Schemas are fetched once for all scenarios. kubeconform v0.8.0 hangs
# reading stdin when -schema-location is given, so it reads a file.
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/schemas"

# Each line is one set of helm arguments.
scenarios=(
  ""
  "--values $ROOT/test/deploy/values-full.yaml"
  "--values $ROOT/test/deploy/values-full.yaml --set persistence.existingClaim=tempogate-state"
  "--set persistence.enabled=false --set serviceAccount.create=false"
  "--values $ROOT/test/deploy/values-smoke.yaml"
  "--values $ROOT/examples/kind/values.yaml"
  "--values $ROOT/test/deploy/values-smoke.yaml --values $ROOT/test/deploy/values-postgres.yaml"
  "--values $ROOT/test/deploy/values-postgres.yaml --set replicaCount=3"
  "--values $ROOT/test/deploy/values-full.yaml --values $ROOT/test/deploy/values-postgres.yaml --set autoscaling.enabled=true --set autoscaling.targetMemoryUtilizationPercentage=80 --set state.postgres.listenDsnSecretRef.name=tempogate-postgres --set state.postgres.listenDsnSecretRef.key=listen-dsn --set state.postgres.connMaxIdleTime=10m"
)

failures=0
for args in "${scenarios[@]}"; do
  label="${args:-defaults}"
  label="${label//$ROOT\//}"
  # shellcheck disable=SC2086 # word splitting of $args is intended
  if out=$(helm lint --strict "$CHART" $args 2>&1); then
    echo "ok   helm lint --strict ($label)"
  else
    echo "FAIL helm lint --strict ($label):" >&2
    echo "$out" >&2
    failures=$((failures + 1))
  fi

  # shellcheck disable=SC2086
  if ! out=$(helm template "$RELEASE" "$CHART" $args 2>&1); then
    echo "FAIL helm template ($label):" >&2
    echo "$out" >&2
    failures=$((failures + 1))
    continue
  fi
  printf '%s\n' "$out" >"$work/manifests.yaml"
  for version in $KUBE_VERSIONS; do
    if out=$(kubeconform -strict -summary -kubernetes-version "$version" -cache "$work/schemas" \
      -schema-location default \
      -schema-location "$CRDS_CATALOG/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json" \
      "$work/manifests.yaml" 2>&1); then
      echo "ok   kubeconform -strict k8s $version ($label): $out"
    else
      echo "FAIL kubeconform -strict k8s $version ($label):" >&2
      echo "$out" >&2
      failures=$((failures + 1))
    fi
  done
done

if [ "$failures" -ne 0 ]; then
  echo "FAIL: $failures chart lint/schema check(s) failed" >&2
  exit 1
fi
echo "PASS: chart lints and every rendered manifest is schema-valid"
