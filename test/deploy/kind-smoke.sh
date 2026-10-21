#!/usr/bin/env bash
# Deployment smoke test for the Helm chart: render it, install it into a
# throwaway kind cluster with a locally built image, and assert the pod's
# `migrate` initContainer succeeds and the pod becomes Ready; then upgrade the
# release and assert a fresh pod migrates again after the old one is gone;
# then run `helm test`. The cluster is always deleted on exit.
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
    kubectl --context "$kubectx" describe pod -l "app.kubernetes.io/instance=$RELEASE" >&2 || true
    kubectl --context "$kubectx" logs "deploy/$RELEASE" -c migrate --tail=50 >&2 || true
    kubectl --context "$kubectx" logs "deploy/$RELEASE" -c tempogate --tail=50 >&2 || true
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

pod_selector="app.kubernetes.io/name=tempogate,app.kubernetes.io/instance=$RELEASE"

# assert_migrated: exactly one tempogate pod, Ready, whose migrate
# initContainer exited 0 after bringing the schema up to date. Prints the
# pod's UID.
assert_migrated() {
  k rollout status "deploy/$RELEASE" --timeout="$TIMEOUT" >&2
  k wait --for=condition=Ready pod -l "$pod_selector" --timeout="$TIMEOUT" >&2
  local pods pod code
  pods=$(k get pod -l "$pod_selector" -o name)
  if [ "$(wc -l <<<"$pods")" != 1 ]; then
    echo "FAIL: want exactly one tempogate pod, got: $pods" >&2
    return 1
  fi
  pod="${pods#pod/}"
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
  k get pod "$pod" -o jsonpath='{.metadata.uid}'
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
first=$(assert_migrated)

echo "==> helm upgrade: a fresh pod must migrate again on the same volume"
# A pod-template change forces a new pod; Recreate deletes the old one first.
helm upgrade "$RELEASE" "$CHART" --kube-context "$kubectx" \
  --values "$VALUES" "${set_image[@]}" \
  --set-string podAnnotations.tempogate-smoke/upgrade=1 \
  --wait --timeout "$TIMEOUT"
second=$(assert_migrated)
if [ "$first" = "$second" ]; then
  echo "FAIL: helm upgrade did not replace the pod ($first)" >&2
  exit 1
fi

echo "==> helm test"
helm test "$RELEASE" --kube-context "$kubectx" --timeout "$TIMEOUT" --logs

echo "PASS: chart installs, upgrades and passes helm test in kind"
