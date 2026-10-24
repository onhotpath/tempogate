#!/usr/bin/env bash
# Deployment smoke test for the Helm chart: render it, install it into a
# throwaway kind cluster with a locally built image, and assert the pod's
# `migrate` initContainer succeeds and the pod becomes Ready; then upgrade the
# release and assert a fresh pod migrates again after the old one is gone;
# then run `helm test`. A second phase does the same in HA mode: two
# replicas on a throwaway Postgres (test/deploy/postgres.yaml) that share one
# signing key and roll on upgrade. The cluster is always deleted on exit.
#
#   test/deploy/kind-smoke.sh            # or: make test-deploy-kind
#
# Env:
#   IMAGE       image to test (default tempogate:smoke)
#   SKIP_BUILD  set to 1 to use an already built IMAGE
#   CLUSTER     kind cluster name (default tempogate-smoke)
#   KIND_CONFIG optional kind cluster config, e.g. one enabling the
#               KubeletInUserNamespace feature gate when Docker itself runs
#               in an unprivileged container (no /dev/kmsg)
set -euo pipefail

IMAGE="${IMAGE:-tempogate:smoke}"
CLUSTER="${CLUSTER:-tempogate-smoke}"
RELEASE=tempogate
PG_RELEASE=tempogate-pg
TIMEOUT=5m

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT/charts/tempogate"
VALUES="$ROOT/test/deploy/values-smoke.yaml"
PG_VALUES="$ROOT/test/deploy/values-postgres.yaml"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need docker; need kind; need kubectl; need helm; need openssl

repo="${IMAGE%:*}"
tag="${IMAGE##*:}"
set_image=(--set "image.repository=$repo" --set "image.tag=$tag" --set image.pullPolicy=Never)

echo "==> helm template: extraEnv must reach the migrate initContainer and serve"
deploy=$(helm template "$RELEASE" "$CHART" --values "$VALUES" "${set_image[@]}" \
  --show-only templates/deployment.yaml)
if [ "$(grep -c 'name: STATE_SQLITE_BUSY_TIMEOUT' <<<"$deploy")" != 2 ]; then
  echo "FAIL: extraEnv (STATE_SQLITE_BUSY_TIMEOUT) must appear in both containers:" >&2
  echo "$deploy" >&2
  exit 1
fi
echo "    ok"

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> building $IMAGE"
  DOCKER_BUILDKIT=1 docker build -t "$IMAGE" -f "$ROOT/Dockerfile" "$ROOT"
fi

echo "==> kind cluster '$CLUSTER'"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kubectx="kind-$CLUSTER"
cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "==> diagnostics" >&2
    kubectl --context "$kubectx" get all,pvc -o wide >&2 || true
    for r in "$RELEASE" "$PG_RELEASE"; do
      kubectl --context "$kubectx" describe pod -l "app.kubernetes.io/instance=$r" >&2 || true
      kubectl --context "$kubectx" logs -l "app.kubernetes.io/instance=$r" -c migrate --prefix --tail=50 >&2 || true
      kubectl --context "$kubectx" logs -l "app.kubernetes.io/instance=$r" -c tempogate --prefix --tail=50 >&2 || true
    done
    kubectl --context "$kubectx" logs deploy/postgres --tail=50 >&2 || true
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT
kind create cluster --name "$CLUSTER" ${KIND_CONFIG:+--config "$KIND_CONFIG"} --wait 2m
kind load docker-image "$IMAGE" --name "$CLUSTER"

k() { kubectl --context "$kubectx" "$@"; }

# Demo-only secret material, scoped to this throwaway cluster.
k create secret generic tempogate-smoke \
  --from-literal=session-signing-key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" \
  --from-literal=client-secrets="tempogate-device-ui:smoke-$(openssl rand -hex 8)"

# assert_migrated RELEASE COUNT: exactly COUNT tempogate pods of RELEASE, all
# Ready, each with a migrate initContainer that exited 0 after bringing the
# schema up to date. Prints the pods' UIDs, sorted, one per line.
assert_migrated() {
  local release="$1" count="$2" selector pods pod code
  selector="app.kubernetes.io/name=tempogate,app.kubernetes.io/instance=$release"
  k rollout status "deploy/$release" --timeout="$TIMEOUT" >&2
  # A rolling update leaves the old pods Terminating for a while.
  for pod in $(k get pod -l "$selector" -o jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.name}{" "}{end}'); do
    k wait --for=delete "pod/$pod" --timeout="$TIMEOUT" >&2
  done
  k wait --for=condition=Ready pod -l "$selector" --timeout="$TIMEOUT" >&2
  pods=$(k get pod -l "$selector" -o name)
  if [ "$(wc -l <<<"$pods")" != "$count" ]; then
    echo "FAIL: want exactly $count $release pod(s), got: $pods" >&2
    return 1
  fi
  for pod in $pods; do
    pod="${pod#pod/}"
    code=$(k get pod "$pod" -o jsonpath='{.status.initContainerStatuses[?(@.name=="migrate")].state.terminated.exitCode}')
    if [ "$code" != 0 ]; then
      echo "FAIL: migrate initContainer of $pod exit code '$code', want 0" >&2
      return 1
    fi
    if ! k logs "$pod" -c migrate | grep -q 'migrations up to date'; then
      echo "FAIL: migrate initContainer of $pod did not log 'migrations up to date'" >&2
      k logs "$pod" -c migrate >&2 || true
      return 1
    fi
    echo "    $pod: migrate exited 0, pod Ready" >&2
  done
  k get pod -l "$selector" -o jsonpath='{range .items[*]}{.metadata.uid}{"\n"}{end}' | sort
}

echo "==> helm install"
helm install "$RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" "${set_image[@]}" \
  --wait --timeout "$TIMEOUT"
if [ -n "$(k get job -l "app.kubernetes.io/instance=$RELEASE" -o name)" ]; then
  echo "FAIL: the chart must not create a migrate Job" >&2
  exit 1
fi

echo "==> migrate initContainer must succeed and the pod become Ready"
first=$(assert_migrated "$RELEASE" 1)

echo "==> helm upgrade: a fresh pod must migrate again on the same volume"
# A pod-template change forces a new pod; Recreate deletes the old one first.
helm upgrade "$RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" "${set_image[@]}" \
  --set-string podAnnotations.tempogate-smoke/upgrade=1 \
  --wait --timeout "$TIMEOUT"
second=$(assert_migrated "$RELEASE" 1)
if [ "$first" = "$second" ]; then
  echo "FAIL: helm upgrade did not replace the pod ($first)" >&2
  exit 1
fi

echo "==> helm test"
helm test "$RELEASE" --kube-context "$kubectx" --timeout "$TIMEOUT" --logs

echo "==> HA mode: uninstall the SQLite release and start Postgres"
helm uninstall "$RELEASE" --kube-context "$kubectx" --wait --timeout "$TIMEOUT"
# Demo-only credentials. sslmode=disable needs the chart's dev-only
# allowInsecureSslMode, which values-postgres.yaml sets.
pg_password="smoke-$(openssl rand -hex 16)"
k create secret generic tempogate-postgres \
  --from-literal=password="$pg_password" \
  --from-literal=dsn="postgres://tempogate:$pg_password@postgres:5432/tempogate?sslmode=disable"
k apply -f "$ROOT/test/deploy/postgres.yaml"
k rollout status deploy/postgres --timeout="$TIMEOUT"

echo "==> helm install: two replicas on one Postgres migrate and become Ready"
helm install "$PG_RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" --values "$PG_VALUES" "${set_image[@]}" \
  --wait --timeout "$TIMEOUT"
if [ -n "$(k get pvc -l "app.kubernetes.io/instance=$PG_RELEASE" -o name)" ]; then
  echo "FAIL: the chart must not create a PVC with state.driver=postgres" >&2
  exit 1
fi
first=$(assert_migrated "$PG_RELEASE" 2)
# Replicas booting together on an empty database generate one key between them.
keypairs=$(k exec deploy/postgres -- psql -U tempogate -d tempogate -tAc 'SELECT count(*) FROM keypairs')
if [ "$keypairs" != 1 ]; then
  echo "FAIL: two replicas on an empty database must generate one signing key, got $keypairs" >&2
  exit 1
fi
echo "    both replicas share one signing key"

echo "==> helm upgrade: the replicas roll, each new pod migrating first"
helm upgrade "$PG_RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" --values "$PG_VALUES" "${set_image[@]}" \
  --set-string podAnnotations.tempogate-smoke/upgrade=1 \
  --wait --timeout "$TIMEOUT"
strategy=$(k get deploy "$PG_RELEASE" -o jsonpath='{.spec.strategy.type}')
if [ "$strategy" != RollingUpdate ]; then
  echo "FAIL: the Postgres Deployment strategy is '$strategy', want RollingUpdate" >&2
  exit 1
fi
second=$(assert_migrated "$PG_RELEASE" 2)
if [ -n "$(comm -12 <(echo "$first") <(echo "$second"))" ]; then
  echo "FAIL: helm upgrade did not replace every pod" >&2
  exit 1
fi

echo "==> helm test (HA mode)"
helm test "$PG_RELEASE" --kube-context "$kubectx" --timeout "$TIMEOUT" --logs

echo "PASS: chart installs, upgrades and passes helm test in kind, on SQLite and on Postgres with two replicas"
