#!/usr/bin/env bash
# Deployment smoke test for the Helm chart: render it, install it into a
# throwaway kind cluster with a locally built image, and assert the migrate
# Job completes and the tempogate pod becomes Ready. The cluster is always
# deleted on exit.
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
TIMEOUT=5m

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHART="$ROOT/charts/tempogate"
VALUES="$ROOT/test/deploy/values-smoke.yaml"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need docker; need kind; need kubectl; need helm; need openssl

repo="${IMAGE%:*}"
tag="${IMAGE##*:}"
set_image=(--set "image.repository=$repo" --set "image.tag=$tag" --set image.pullPolicy=Never)

echo "==> helm template: extraEnv must reach the migrate Job"
job=$(helm template "$RELEASE" "$CHART" --values "$VALUES" "${set_image[@]}" \
  --show-only templates/migrate-job.yaml)
if ! grep -q 'STATE_SQLITE_BUSY_TIMEOUT' <<<"$job"; then
  echo "FAIL: extraEnv (STATE_SQLITE_BUSY_TIMEOUT) missing from the migrate Job:" >&2
  echo "$job" >&2
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
    kubectl --context "$kubectx" logs -l app.kubernetes.io/component=migrate --tail=50 >&2 || true
    kubectl --context "$kubectx" logs "deploy/$RELEASE" --tail=50 >&2 || true
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

echo "==> helm install"
helm install "$RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" "${set_image[@]}" \
  --wait --wait-for-jobs --timeout "$TIMEOUT"

echo "==> migrate Job must complete"
k wait --for=condition=complete job -l app.kubernetes.io/component=migrate --timeout="$TIMEOUT"

echo "==> tempogate pod must be Ready"
k rollout status "deploy/$RELEASE" --timeout="$TIMEOUT"
k wait --for=condition=Ready pod -l app.kubernetes.io/name=tempogate,app.kubernetes.io/component!=migrate --timeout="$TIMEOUT"

echo "PASS: chart installs cleanly in kind"
