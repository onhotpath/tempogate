#!/usr/bin/env bash
# Run inside kind-smoke.sh's disposable cluster, with its Secrets and Postgres.
# Each baseline uses its published default image, then upgrades to IMAGE.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASELINE_CHART="${BASELINE_CHART:?set BASELINE_CHART to the unpacked released chart}"
IMAGE="${IMAGE:?set IMAGE to the locally built candidate}"
CONTEXT="${CONTEXT:?set CONTEXT to the disposable kind context}"
work=$(mktemp -d)
forward_pid=""
stop_forward() {
  if [ -n "$forward_pid" ]; then
    kill "$forward_pid" 2>/dev/null || true
    wait "$forward_pid" 2>/dev/null || true
    forward_pid=""
  fi
}
cleanup() { stop_forward; rm -rf "$work"; }
trap cleanup EXIT
k() { kubectl --context "$CONTEXT" "$@"; }
# Launch kubectl directly: backgrounding k() tracks a shell wrapper whose
# termination leaves kubectl running and holding the local port.
start_forward() {
  stop_forward
  kubectl --context "$CONTEXT" port-forward "service/$release" 18000:8000 >"$work/public-forward.log" 2>&1 &
  forward_pid=$!
  curl --retry 30 --retry-delay 1 --retry-all-errors --max-time 2 -fsS \
    http://127.0.0.1:18000/readyz > /dev/null 2>"$work/ready.log" || {
      cat "$work/public-forward.log" "$work/ready.log" >&2
      return 1
    }
}
# The admin port-forward is separate because the public Service exposes no
# admin port. Avoid printing credentials or the minted JWT into CI logs.
admin_request() {
  local method="$1" path="$2"; shift 2
  kubectl --context "$CONTEXT" port-forward "service/$release-admin" 18081:8081 >"$work/admin-forward.log" 2>&1 &
  local admin_pid=$!
  # Wait for the listener without retrying POST, which could mint twice.
  local ready=0
  for _ in $(seq 1 50); do
    if grep -Fq 'Forwarding from 127.0.0.1:' "$work/admin-forward.log"; then ready=1; break; fi
    if ! kill -0 "$admin_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  local status=0
  if [ "$ready" != 1 ]; then
    cat "$work/admin-forward.log" >&2
    status=1
  else
    curl -fsS --max-time 10 -X "$method" -H "Authorization: Bearer $admin_token" \
      -H 'Content-Type: application/json' "$@" "http://127.0.0.1:18081$path" || status=$?
  fi
  kill "$admin_pid" 2>/dev/null || true
  wait "$admin_pid" 2>/dev/null || true
  return "$status"
}

baseline_image=$(helm show chart "$BASELINE_CHART" | yq -r '.appVersion')
baseline_repo=$(yq -r '.image.repository' "$BASELINE_CHART/values.yaml")
docker pull "$baseline_repo:$baseline_image"
kind load docker-image "$baseline_repo:$baseline_image" --name "${CONTEXT#kind-}"
admin_token=$(openssl rand -hex 32)
admin_hash=$(printf '%s' "$admin_token" | openssl dgst -sha256 -r | cut -d' ' -f1)
k create secret generic tempogate-upgrade-admin --from-literal=hash="$admin_hash"
secret_uid=$(k get secret tempogate-smoke -o jsonpath='{.metadata.uid}')
expires=$(python3 -c 'from datetime import datetime,timedelta,timezone; print((datetime.now(timezone.utc)+timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')

modes=(sqlite)
if [ "$(yq '.state.driver' "$BASELINE_CHART/values.yaml")" = sqlite ]; then
  modes+=(postgres)
else
  echo "Baseline predates PostgreSQL chart support; testing its SQLite upgrade only (fresh PostgreSQL install is covered separately)"
fi
for mode in "${modes[@]}"; do
  release="tempogate-upgrade-$mode"
  values=(--values "$ROOT/test/deploy/values-smoke.yaml"
    --set service.admin.enabled=true
    --set admin.tokenSha256SecretRef.name=tempogate-upgrade-admin
    --set admin.tokenSha256SecretRef.key=hash)
  if [ "$mode" = postgres ]; then
    # Isolate the old binary from the database already migrated by the
    # fresh-install smoke test.
    k exec deploy/postgres -- psql -U tempogate -d tempogate -c 'CREATE DATABASE tempogate_upgrade'
    upgrade_dsn=$(k get secret tempogate-postgres -o jsonpath='{.data.dsn}' | openssl base64 -d -A)
    upgrade_dsn="${upgrade_dsn/\/tempogate?/\/tempogate_upgrade?}"
    k create secret generic tempogate-upgrade-postgres --from-literal=dsn="$upgrade_dsn"
    values+=(--values "$ROOT/test/deploy/values-postgres.yaml"
      --set state.postgres.dsnSecretRef.name=tempogate-upgrade-postgres)
  fi
  echo "==> released chart: install $release with its default image"
  helm install "$release" "$BASELINE_CHART" --kube-context "$CONTEXT" "${values[@]}" --wait --timeout 5m
  start_forward
  curl -fsS http://127.0.0.1:18000/.well-known/jwks.json | jq -Se '.keys | select(length > 0)' >"$work/jwks-before.json"
  admin_request POST /admin/keys --data "{\"namespace\":\"upgrade-proof\",\"role\":\"read\",\"owner\":\"chart-ci\",\"expires_at\":\"$expires\"}" >"$work/minted.json"
  id=$(jq -er '.id' "$work/minted.json")
  admin_request GET "/admin/keys/$id" | jq -S . >"$work/key-before.json"
  stop_forward
  pvc_uid=""
  if [ "$mode" = sqlite ]; then
    pvc_uid=$(k get pvc "$release-state" -o jsonpath='{.metadata.uid}')
  fi

  echo "==> upgrade $release to the candidate chart and image"
  helm upgrade "$release" "$ROOT/charts/tempogate" --kube-context "$CONTEXT" "${values[@]}" \
    --set "image.repository=${IMAGE%:*}" --set "image.tag=${IMAGE##*:}" --set image.pullPolicy=Never \
    --wait --timeout 5m
  start_forward
  curl -fsS http://127.0.0.1:18000/.well-known/jwks.json | jq -Se '.keys | select(length > 0)' >"$work/jwks-after.json"
  diff -u "$work/jwks-before.json" "$work/jwks-after.json"
  admin_request GET "/admin/keys/$id" | jq -S . >"$work/key-after.json"
  diff -u "$work/key-before.json" "$work/key-after.json"
  [ "$secret_uid" = "$(k get secret tempogate-smoke -o jsonpath='{.metadata.uid}')" ]
  if [ "$mode" = sqlite ]; then
    [ "$pvc_uid" = "$(k get pvc "$release-state" -o jsonpath='{.metadata.uid}')" ]
  fi
  helm test "$release" --kube-context "$CONTEXT" --timeout 5m --logs
  stop_forward
  helm uninstall "$release" --kube-context "$CONTEXT" --wait --timeout 5m
  echo "PASS: $mode upgrade preserves signing keys, integration-key metadata, and existing storage/Secrets"
done
