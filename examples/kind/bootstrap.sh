#!/usr/bin/env bash
# Deploy tempogate to a local kind cluster from a fresh checkout, with no
# published image required: build the image, load it into the cluster, install
# the chart with the kind overlay, wait for readiness, and prove /healthz.
#
#   cd examples/kind && bash bootstrap.sh
#
# Idempotent: re-running reuses the cluster and upgrades the release. Tear
# down with:  kind delete cluster --name "$CLUSTER"
set -euo pipefail

CLUSTER="${CLUSTER:-tempogate-demo}"
RELEASE="${RELEASE:-tempogate}"
IMAGE="tempogate:kind-local"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CHART_DIR="$REPO_ROOT/charts/tempogate"

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' is required but not on PATH" >&2; exit 1; }; }
need docker; need kind; need kubectl; need helm; need openssl

echo "==> kind cluster '$CLUSTER'"
if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  kind create cluster --name "$CLUSTER"
else
  echo "    exists, reusing"
fi

# Build from source and load into the node so no registry/published image is
# needed. pullPolicy below is IfNotPresent so kind serves the loaded image.
echo "==> building $IMAGE"
docker build -t "$IMAGE" "$REPO_ROOT"

echo "==> loading $IMAGE into '$CLUSTER'"
kind load docker-image "$IMAGE" --name "$CLUSTER"

# The Secret examples/kind/values.yaml references. Created once and reused on
# re-runs: the session signing key must stay stable across restarts.
echo "==> secret tempogate-kind"
if ! kubectl get secret tempogate-kind >/dev/null 2>&1; then
  kubectl create secret generic tempogate-kind \
    --from-literal=session-signing-key="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" \
    --from-literal=client-secrets="tempogate-device-ui:$(openssl rand -hex 32)"
else
  echo "    exists, reusing"
fi

echo "==> helm upgrade --install $RELEASE"
helm upgrade --install "$RELEASE" "$CHART_DIR" \
  --values "$SCRIPT_DIR/values.yaml" \
  --set image.repository=tempogate \
  --set image.tag=kind-local \
  --set image.pullPolicy=IfNotPresent \
  --wait --timeout 5m

echo "==> waiting for rollout"
kubectl rollout status "deploy/$RELEASE" --timeout=180s

# Prove /healthz through a short-lived port-forward, cleaned up on exit.
echo "==> probing /healthz"
kubectl port-forward "svc/$RELEASE" 18000:8000 >/dev/null 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  if curl -fsS http://127.0.0.1:18000/healthz >/dev/null 2>&1; then
    echo "    /healthz -> 200"
    OK=1
    break
  fi
  sleep 1
done
if [ "${OK:-0}" != "1" ]; then
  echo "error: /healthz never returned 200" >&2
  exit 1
fi

cat <<EOF

tempogate is running in kind cluster '$CLUSTER'.

  kubectl port-forward svc/$RELEASE 8000:8000
  curl http://127.0.0.1:8000/healthz

This overlay only proves the server boots, migrates, and serves /healthz.
Wiring real Google SSO + a Temporal cluster:
  - upstream Google client : ../google-oauth-setup.md
  - point Temporal at JWKS : ./temporal-values.yaml
  - end-to-end walkthrough : ../../docs/getting-started.md

Tear down:  kind delete cluster --name $CLUSTER
EOF
