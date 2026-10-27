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
expect_render_error "updateStrategy RollingUpdate is rejected" "Recreate" --set updateStrategy.type=RollingUpdate
expect_eq "replicaCount=0 still renders (scale to zero)" "0" \
  "$(render --set replicaCount=0 | yq 'select(.kind == "Deployment") | .spec.replicas')"
expect_eq "no HorizontalPodAutoscaler is rendered" "" "$(yq 'select(.kind == "HorizontalPodAutoscaler")' <<<"$manifests")"
expect_eq "no PodDisruptionBudget is rendered" "" "$(yq 'select(.kind == "PodDisruptionBudget")' <<<"$manifests")"
expect_eq "SQLite Deployment uses Recreate" "Recreate" "$(q Deployment .spec.strategy.type)"
expect_eq "STATE_DRIVER defaults to sqlite" "sqlite" "$(q ConfigMap .data.STATE_DRIVER)"
expect_eq "LOG_FORMAT defaults to json" "json" "$(q ConfigMap .data.LOG_FORMAT)"
expect_render_error "an unknown state.driver is rejected" "state.driver" --set state.driver=mysql

echo "==> HA mode on Postgres"
PG_VALUES="$ROOT/test/deploy/values-postgres.yaml"
expect_render_error "Postgres without a DSN Secret is rejected" "dsnSecretRef" --set state.driver=postgres
pg=$(render --values "$PG_VALUES" --set replicaCount=3) || fail "Postgres render with replicaCount=3: $pg"
pgq() { yq "select(.kind == \"$1\")" <<<"$pg" | yq "$2"; }
pginit() { pgq Deployment ".spec.template.spec.initContainers[] | select(.name == \"migrate\") | $1"; }
expect_eq "Postgres renders replicaCount=3" "3" "$(pgq Deployment .spec.replicas)"
expect_eq "Postgres Deployment uses RollingUpdate" "RollingUpdate" "$(pgq Deployment .spec.strategy.type)"
expect_eq "updateStrategy overrides the Postgres default" "Recreate" \
  "$(render --values "$PG_VALUES" --set updateStrategy.type=Recreate | yq 'select(.kind == "Deployment") | .spec.strategy.type')"
expect_eq "Postgres renders no PVC" "" "$(yq 'select(.kind == "PersistentVolumeClaim") | .metadata.name' <<<"$pg")"
expect_eq "Postgres pod has no state volume" "0" \
  "$(pgq Deployment '[.spec.template.spec.volumes[] | select(.name == "state")] | length')"
expect_eq "ConfigMap sets STATE_DRIVER=postgres" "postgres" "$(pgq ConfigMap .data.STATE_DRIVER)"
expect_eq "ConfigMap has no STATE_SQLITE_PATH on Postgres" "null" "$(pgq ConfigMap .data.STATE_SQLITE_PATH)"
expect_eq "ConfigMap points STATE_POSTGRES_DSN_FILE at the mounted Secret" "/etc/tempogate/postgres/dsn" \
  "$(pgq ConfigMap .data.STATE_POSTGRES_DSN_FILE)"
expect_eq "ConfigMap never holds a DSN" "0" \
  "$(pgq ConfigMap '.data | keys | map(select(. == "STATE_POSTGRES_DSN" or . == "STATE_POSTGRES_LISTEN_DSN")) | length')"
expect_eq "DSN Secret key is mounted as the dsn file" "tempogate-postgres:dsn->dsn" \
  "$(pgq Deployment '.spec.template.spec.volumes[] | select(.name == "postgres-dsn") | .secret.secretName + ":" + .secret.items[0].key + "->" + .secret.items[0].path')"
for c in migrate tempogate; do
  expect_eq "$c mounts the DSN Secret read-only" "/etc/tempogate/postgres:true" \
    "$(pgq Deployment "(.spec.template.spec.initContainers + .spec.template.spec.containers)[] | select(.name == \"$c\") |
      .volumeMounts[] | select(.name == \"postgres-dsn\") | .mountPath + \":\" + (.readOnly | tostring)")"
done
expect_eq "Postgres migrate initContainer still gets no secret env" "0" \
  "$(pginit '[.env // [] | .[] | select(.valueFrom.secretKeyRef)] | length')"
pg_listen=$(render --values "$PG_VALUES" --set state.postgres.listenDsnSecretRef.name=l \
  --set state.postgres.listenDsnSecretRef.key=k | yq 'select(.kind == "Deployment")')
expect_eq "listenDsnSecretRef reaches serve as STATE_POSTGRES_LISTEN_DSN" "l:k" \
  "$(yq '.spec.template.spec.containers[0].env[] | select(.name == "STATE_POSTGRES_LISTEN_DSN") | .valueFrom.secretKeyRef.name + ":" + .valueFrom.secretKeyRef.key' <<<"$pg_listen")"
expect_eq "listenDsnSecretRef does not reach migrate" "0" \
  "$(yq '.spec.template.spec.initContainers[] | select(.name == "migrate") | [.env // [] | .[] | select(.name == "STATE_POSTGRES_LISTEN_DSN")] | length' <<<"$pg_listen")"
expect_eq "listenDsnSecretRef is ignored on SQLite" "0" \
  "$(render --set state.postgres.listenDsnSecretRef.name=l --set state.postgres.listenDsnSecretRef.key=k |
    yq 'select(.kind == "Deployment")' |
    yq '[.spec.template.spec.containers[0].env // [] | .[] | select(.name == "STATE_POSTGRES_LISTEN_DSN")] | length')"
expect_eq "PodDisruptionBudget renders when enabled" "1" "$(pgq PodDisruptionBudget .spec.maxUnavailable)"
pg_hpa=$(render --values "$PG_VALUES" --set autoscaling.enabled=true)
expect_eq "autoscaling renders an HPA on Postgres" "2-5" \
  "$(yq 'select(.kind == "HorizontalPodAutoscaler") | (.spec.minReplicas | tostring) + "-" + (.spec.maxReplicas | tostring)' <<<"$pg_hpa")"
expect_eq "autoscaling leaves replicas to the HPA" "null" \
  "$(yq 'select(.kind == "Deployment") | .spec.replicas' <<<"$pg_hpa")"
expect_render_error "autoscaling without a target is rejected" "targetCPUUtilizationPercentage" \
  --values "$PG_VALUES" --set autoscaling.enabled=true --set autoscaling.targetCPUUtilizationPercentage=0

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
# A Postgres CA bundle for sslrootcert must reach migrate as well as serve.
expect_eq "volumeMounts reach the migrate initContainer" "/etc/db-ca" \
  "$(render --set 'volumes[0].name=db-ca' --set 'volumes[0].emptyDir.medium=Memory' \
    --set 'volumeMounts[0].name=db-ca' --set 'volumeMounts[0].mountPath=/etc/db-ca' |
    yq 'select(.kind == "Deployment") | .spec.template.spec.initContainers[] | select(.name == "migrate") |
      .volumeMounts[] | select(.name == "db-ca") | .mountPath')"

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

echo "==> public routing and admin isolation"
expect_render_error "admin Service requires a token Secret" "admin.tokenSha256SecretRef" --set service.admin.enabled=true
expect_eq "admin Service is absent by default" "tempogate" "$(q Service .metadata.name)"
expect_eq "admin listener is not exposed by default" "null" "$(q ConfigMap .data.ADMIN_LISTENER)"
routed=$(render --namespace routing-test --set fullnameOverride=custom-gate --set service.port=9000 \
  --set service.admin.enabled=true --set service.admin.port=9001 \
  --set admin.tokenSha256SecretRef.name=admin --set admin.tokenSha256SecretRef.key=hash \
  --set ingress.enabled=true --set httpRoute.enabled=true)
rq() { yq "select(.kind == \"$1\")" <<<"$routed" | yq "$2"; }
expect_eq "public Service exposes only the public port" "9000:http" \
  "$(rq Service 'select(.metadata.name == "custom-gate") | .spec.ports[] | (.port | tostring) + ":" + .targetPort')"
expect_eq "admin Service is separate and internal" "ClusterIP:9001:admin" \
  "$(rq Service 'select(.metadata.name == "custom-gate-admin") | .spec.type + ":" + (.spec.ports[0].port | tostring) + ":" + .spec.ports[0].targetPort')"
expect_eq "Ingress routes only to the public Service" "custom-gate:9000" \
  "$(rq Ingress '.spec.rules[].http.paths[].backend.service | .name + ":" + (.port.number | tostring)')"
expect_eq "HTTPRoute routes only to the public Service" "custom-gate:9000" \
  "$(rq HTTPRoute '.spec.rules[].backendRefs[] | .name + ":" + (.port | tostring)')"
expect_eq "admin listener binds the configured port" "0.0.0.0:9001" "$(rq ConfigMap .data.ADMIN_LISTENER)"
expect_eq "admin allowed hosts follow the Service name and namespace" \
  "custom-gate-admin:9001,custom-gate-admin.routing-test:9001,custom-gate-admin.routing-test.svc:9001,custom-gate-admin.routing-test.svc.cluster.local:9001,127.0.0.1,localhost,[::1]" \
  "$(rq ConfigMap .data.ADMIN_ALLOWED_HOSTS)"

echo "==> configuration changes trigger rollouts"
checksum=$(q Deployment '.spec.template.metadata.annotations."checksum/config"')
changed=$(render --set log.level=debug | yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"')
if [[ "$checksum" =~ ^[a-f0-9]{64}$ ]] && [ "$checksum" != "$changed" ]; then
  pass "ConfigMap change updates the pod checksum"
else
  fail "ConfigMap change must update the pod checksum"
fi
expect_eq "unchanged configuration has a stable checksum" "$checksum" \
  "$(render | yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"')"
expect_eq "non-config values leave the checksum stable" "$checksum" \
  "$(render --set podLabels.test=value | yq 'select(.kind == "Deployment") | .spec.template.metadata.annotations."checksum/config"')"

echo "==> Helm runtime tests"
expect_eq "test hook cleans up successful pods" "before-hook-creation,hook-succeeded" \
  "$(q Pod '.metadata.annotations."helm.sh/hook-delete-policy"')"
expect_eq "runtime test respects issuer sub-paths" 'prefix="/idp"' \
  "$(render --set oidc.issuer=https://example.com/idp/ | yq 'select(.kind == "Pod") | .spec.containers[0].args[0]' | grep '^prefix=')"

if [ "$failures" -ne 0 ]; then
  echo "FAIL: $failures chart assertion(s) failed" >&2
  exit 1
fi
echo "PASS: chart assertions"
