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
  "$(q Deployment '[((.spec.template.spec.initContainers // [])[], .spec.template.spec.containers[]) | .securityContext.seccompProfile.type] | unique | join(",")')"
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

echo "==> migrations run in a migrate initContainer, not a Job"
expect_eq "no Job is rendered" "" "$(yq 'select(.kind == "Job") | .metadata.name' <<<"$manifests")"
expect_eq "no Job is rendered with an existingClaim" "" \
  "$(render --set persistence.existingClaim=my-claim | yq 'select(.kind == "Job") | .metadata.name')"
init() { q Deployment ".spec.template.spec.initContainers[] | select(.name == \"migrate\") | $1"; }
expect_eq "Deployment has a migrate initContainer" "migrate" "$(init .name)"
expect_eq "migrate initContainer runs 'migrate'" '["migrate"]' "$(init '.args | to_json(0)')"
expect_eq "migrate initContainer uses the serve image" \
  "$(q Deployment '.spec.template.spec.containers[0].image')" "$(init .image)"
expect_eq "migrate initContainer gets the ConfigMap env" \
  "$(q ConfigMap .metadata.name)" "$(init '.envFrom[0].configMapRef.name')"
expect_eq "migrate initContainer gets no secrets" "0" \
  "$(init '[.env // [] | .[] | select(.valueFrom.secretKeyRef)] | length')"
expect_eq "migrate initContainer mounts the state volume" "state:/var/lib/tempogate" \
  "$(init '.volumeMounts[] | select(.name == "state") | .name + ":" + .mountPath')"
expect_eq "migrate initContainer has the serve container's securityContext" \
  "$(q Deployment '.spec.template.spec.containers[0].securityContext | to_json(0)')" \
  "$(init '.securityContext | to_json(0)')"
secret_refs=()
for ref in auth.upstream.google.clientIdSecretRef auth.upstream.google.clientSecretSecretRef \
  auth.clientSecretsSecretRef admin.tokenSha256SecretRef oidc.sessionSigningKeySecretRef \
  keys.encryptionKeySecretRef; do
  secret_refs+=(--set "$ref.name=s" --set "$ref.key=k")
done
secret_deploy=$(render "${secret_refs[@]}" | yq 'select(.kind == "Deployment")')
expect_eq "with every secret ref set, serve gets all six secret env vars" "6" \
  "$(yq '[.spec.template.spec.containers[0].env[] | select(.valueFrom.secretKeyRef)] | length' <<<"$secret_deploy")"
expect_eq "with every secret ref set, migrate still gets none (no KEK, no admin token)" "0" \
  "$(yq '.spec.template.spec.initContainers[] | select(.name == "migrate") |
    [.env // [] | .[] | select(.valueFrom.secretKeyRef)] | length' <<<"$secret_deploy")"
expect_eq "extraEnv reaches the migrate initContainer" "7s" \
  "$(render --set 'extraEnv[0].name=STATE_SQLITE_BUSY_TIMEOUT' --set 'extraEnv[0].value=7s' |
    yq 'select(.kind == "Deployment") | .spec.template.spec.initContainers[] | select(.name == "migrate") |
      .env[] | select(.name == "STATE_SQLITE_BUSY_TIMEOUT") | .value')"

# Authorization rules render as indexed env keys, in order, and the default
# as one key; neither is rendered when unset.
authz_cm=$(render --set 'authz.rules[0]=email:alice@example.com=temporal-system:admin' \
  --set 'authz.rules[1]=domain:example.com=orders:read' \
  --set 'authz.defaultPermissions=orders:read' | yq 'select(.kind == "ConfigMap")')
expect_eq "authz.rules[0] renders as OIDC_AUTHZ_RULES_0" "email:alice@example.com=temporal-system:admin" \
  "$(yq '.data.OIDC_AUTHZ_RULES_0' <<<"$authz_cm")"
expect_eq "authz.rules[1] renders as OIDC_AUTHZ_RULES_1" "domain:example.com=orders:read" \
  "$(yq '.data.OIDC_AUTHZ_RULES_1' <<<"$authz_cm")"
expect_eq "authz.defaultPermissions renders as OIDC_AUTHZ_DEFAULT_PERMISSIONS" "orders:read" \
  "$(yq '.data.OIDC_AUTHZ_DEFAULT_PERMISSIONS' <<<"$authz_cm")"
expect_eq "no OIDC_AUTHZ_* key is rendered by default" "0" \
  "$(yq 'select(.kind == "ConfigMap") | .data | keys | map(select(test("^OIDC_AUTHZ_"))) | length' <<<"$manifests")"

if [ "$failures" -ne 0 ]; then
  echo "FAIL: $failures chart assertion(s) failed" >&2
  exit 1
fi
echo "PASS: chart assertions"
