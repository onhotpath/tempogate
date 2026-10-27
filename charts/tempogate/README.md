# tempogate Helm chart

Drop-in OIDC provider and OAuth2 authorization server for self-hosted
[Temporal](https://temporal.io/). By default this chart deploys a single
tempogate instance backed by a SQLite state store on a
PersistentVolumeClaim. With `state.driver=postgres` it runs any number of
replicas on a shared PostgreSQL 15+ database instead (HA mode).

## Prerequisites

- Kubernetes >= 1.25
- Helm >= 3.8 (OCI support; the chart is also published as an OCI artifact)
- SQLite (default): a default StorageClass (or set
  `persistence.storageClass` / `persistence.existingClaim`)
- HA mode: a PostgreSQL 15+ database reachable with `sslmode=verify-full`

## Install

From the repo checkout:

```bash
helm install tempogate ./charts/tempogate \
  --values examples/kind/values.yaml
```

From the published OCI registry:

```bash
helm install tempogate oci://ghcr.io/onhotpath/charts/tempogate \
  --version 0.5.0
```

Verify:

```bash
kubectl rollout status deploy/tempogate
kubectl port-forward svc/tempogate 8000:8000 &
curl -fsS http://127.0.0.1:8000/healthz
```

## Architecture notes

- **One replica on SQLite.** The default state store is SQLite on one
  ReadWriteOnce PVC, and SQLite allows exactly one writer. With
  `state.driver=sqlite`, `replicaCount` MUST stay `0` or `1` and
  `autoscaling` MUST stay disabled (the chart refuses to render
  otherwise). The Deployment uses the `Recreate` strategy so an update
  never runs two pods against the same volume.
- **Several replicas on PostgreSQL.** With `state.driver=postgres` (see
  [HA mode](#ha-mode-on-postgresql)) the chart renders no PVC, accepts any
  `replicaCount`, can render a HorizontalPodAutoscaler and a
  PodDisruptionBudget, and rolls updates (`RollingUpdate`).
- **Separate admin listener.** `service.port` serves the public OIDC/OAuth2
  surface together with `/healthz` and `/readyz`. The admin API
  (`/admin/keys`, `/admin/signing-keys`, `/admin/sessions`) has its own
  listener, on the pod's loopback by default (reach it with `kubectl
  port-forward`). `service.admin.enabled=true` binds
  it on all pod interfaces behind a separate `<fullname>-admin` Service that
  no Ingress/HTTPRoute targets, and requires `admin.tokenSha256SecretRef`.
- **No API docs.** The OpenAPI document and docs page (`API_DOCS_ENABLED`)
  are for a local dev stack only: `serve` refuses to start with them on
  unless `OIDC_ISSUER` is plain `http://`, so they cannot be enabled in an
  https deployment, `extraEnv` included, and the admin listener never
  serves them. Get the specs with `tempogate gen-oas` and
  `tempogate gen-oas --admin` instead.
- **Metrics are not scraped by the chart.** Prometheus `GET /metrics` is
  served on the admin listener, outside `/admin/*`: it needs no admin token
  and is not Host-checked, so the listener's reachability is its only access
  control. With `service.admin.enabled=false` (the default) it is on the
  pod's loopback only. With `service.admin.enabled=true` a scraper inside the
  cluster can reach it through the `<fullname>-admin` Service; restrict that
  Service with a NetworkPolicy. The chart ships no ServiceMonitor or scrape
  annotations, and the admin listener must never sit behind a public Service
  or Ingress. See
  [docs/operations.md](../../docs/operations.md#observability).
- **Probes.** `livenessProbe` hits `/healthz` (process only);
  `readinessProbe` hits `/readyz`, which also returns `503` while the
  state store is unavailable, taking the pod out of rotation without
  restarting it.
- **Schema migrations** run in a `migrate` initContainer of the
  tempogate pod, before `serve` starts. On SQLite, with one replica and
  the `Recreate` strategy, the previous pod has exited before the new
  pod's `migrate` runs, so a migration never races a running server or
  needs a second ReadWriteOnce attachment, on install, upgrade, and
  rollback alike. On Postgres every pod runs it; concurrent runs
  serialize on a Postgres advisory lock and apply each version once. It
  is not a Helm hook: a hook Job would either own the chart's PVC
  lifecycle or race the old pod for the volume. Read the migration output with
  `kubectl logs <pod> -c migrate`. Chart releases up to 0.3.0 ran a
  separate `<release>-migrate-<revision>` Job instead; Helm removes it on
  the first upgrade to this version.
- **State is release-managed on SQLite.** The chart-managed PVC is removed
  on `helm uninstall` (signing keypair + refresh tokens included). To keep
  state across an uninstall, pre-create a PVC and set
  `persistence.existingClaim`. The chart never manages a Postgres
  database.

## HA mode on PostgreSQL

Create the database and a role that can create tables in its default
schema, then store the connection string in a Secret:

```bash
kubectl create secret generic tempogate-postgres \
  --from-literal=dsn='postgres://tempogate:...@db.example.com:5432/tempogate?sslmode=verify-full&sslrootcert=/etc/tempogate/db-ca/ca.pem&require_auth=scram-sha-256'
```

```yaml
replicaCount: 3
state:
  driver: postgres
  postgres:
    dsnSecretRef: { name: tempogate-postgres, key: dsn }
# The server's CA bundle for sslrootcert, mounted into serve and migrate.
volumes:
  - name: db-ca
    configMap: { name: db-ca }
volumeMounts:
  - name: db-ca
    mountPath: /etc/tempogate/db-ca
    readOnly: true
podDisruptionBudget:
  enabled: true
```

- The DSN is mounted as a file and passed as `STATE_POSTGRES_DSN_FILE`,
  which tempogate re-reads for every new connection: update the Secret
  and a rotated password applies without a restart, once the kubelet
  refreshes the mounted file. It is the only secret the `migrate`
  initContainer gets.
- tempogate refuses a non-loopback host without `sslmode=verify-full`.
  `state.postgres.allowInsecureSslMode` relaxes that for throwaway
  clusters only.
- Size the server's `max_connections` for replicas x
  `state.postgres.maxConns` (default 10), plus one `LISTEN` connection
  per replica. Behind a transaction-mode pooler, point
  `state.postgres.listenDsnSecretRef` at the database directly.
- All replicas share `oidc.sessionSigningKeySecretRef` and the rest of the
  configuration; no sticky sessions are needed. Rate limits are counted
  per replica.
- **Upgrades roll.** The first new pod migrates the shared database while
  the old pods still serve. An older binary ignores schema versions it
  does not know, so this works when the new release's migrations are
  backward compatible; [docs/upgrading.md](../../docs/upgrading.md) names
  any release whose migrations are not. Upgrade to such a release with
  `updateStrategy: {type: Recreate}`.

- **Moving an existing release from SQLite.** Copy its state with
  `tempogate state copy` before switching `state.driver`, and annotate the
  PVC with `helm.sh/resource-policy: keep` first: with Postgres the chart
  no longer renders the claim, so the switching upgrade would delete it.
  [docs/operations.md](../../docs/operations.md#with-the-helm-chart) has
  the steps.

See [docs/configuration.md](../../docs/configuration.md#postgresql) for the
connection-string rules, PgBouncer and change notifications.

## Secrets

The chart never templates secret material. Create the upstream Google
OAuth2 client credentials as a Kubernetes Secret out of band and reference
it:

```bash
kubectl create secret generic tempogate-google \
  --from-literal=client-id=... \
  --from-literal=client-secret=...
```

```yaml
auth:
  upstream:
    google:
      clientIdSecretRef:     { name: tempogate-google, key: client-id }
      clientSecretSecretRef: { name: tempogate-google, key: client-secret }
```

### Authorization

Who may do what in Temporal is plain configuration, not a secret:

```yaml
authz:
  rules:
    - "email:alice@example.com=temporal-system:admin"
    - "domain:example.com=orders:read"
```

Deny is the default: tempogate refuses to start until `authz.rules` or `authz.defaultPermissions` is set.
Upgrading from a release without rules, set `authz.defaultPermissions: "temporal-system:admin"` to keep every admitted user cluster admin while you write rules.
A rule change takes effect after a rollout restart, at each user's next token refresh.
See [docs/authorization.md](../../docs/authorization.md#authorization).

### Admin token

The admin API accepts a bearer token whose SHA-256 is in `ADMIN_TOKEN_SHA256`; only the digest goes into the cluster:

```bash
token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')   # keep in your secret manager
kubectl create secret generic tempogate-admin \
  --from-literal=token-sha256="$(printf %s "$token" | sha256sum | cut -d' ' -f1)"
```

```yaml
admin:
  tokenSha256SecretRef: { name: tempogate-admin, key: token-sha256 }
```

Without it the admin API is locked (401 on every route but `/admin/healthz`).
See [docs/configuration.md](../../docs/configuration.md#admin-api).

## Values

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Pods. With `state.driver=sqlite` MUST be `0` or `1` (single writer); larger values fail the render. Any value with `state.driver=postgres`. |
| `updateStrategy` | `{}` | Deployment strategy. Empty: `Recreate` on SQLite (the only one accepted there), `RollingUpdate` on Postgres. |
| `image.repository` | `ghcr.io/onhotpath/tempogate` | Image repository. |
| `image.tag` | `""` | Image tag; defaults to the chart `appVersion`. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Image pull secrets. |
| `nameOverride` / `fullnameOverride` | `""` | Name overrides. |
| `serviceAccount.create` | `true` | Create a ServiceAccount. |
| `serviceAccount.automount` | `false` | Mount a ServiceAccount token (ServiceAccount and pod spec). tempogate never calls the Kubernetes API. |
| `serviceAccount.name` | `""` | ServiceAccount name (generated when empty). |
| `podAnnotations` / `podLabels` | `{}` | Extra pod metadata. |
| `podSecurityContext` | `runAsNonRoot`, uid/gid/fsGroup `65532`, `seccompProfile: RuntimeDefault` | Pod security context (matches the distroless `nonroot` user). |
| `securityContext` | drop ALL, no privilege escalation, read-only rootfs, `seccompProfile: RuntimeDefault` | Container security context. |
| `service.type` | `ClusterIP` | Service type. |
| `service.port` | `8000` | The public HTTP port (OIDC + health). |
| `service.admin.enabled` | `false` | Bind the admin listener on all pod interfaces and add a `<fullname>-admin` Service. Requires `admin.tokenSha256SecretRef`. |
| `service.admin.type` / `port` | `ClusterIP` / `8081` | Admin Service type and port (also the container port and `ADMIN_LISTENER` port). |
| `listenAddress` | `0.0.0.0` | `HTTP_LISTENER` bind host (must not be loopback in-cluster). |
| `trustedProxies` | `[]` | `HTTP_TRUSTED_PROXIES`: CIDRs of the proxies (e.g. the ingress controller) whose `X-Forwarded-For` is believed for per-client rate limits. Empty: every client behind the ingress shares one budget. See [docs/hardening.md](../../docs/hardening.md#abuse-controls). |
| `ingress.enabled` | `false` | Enable Ingress. |
| `ingress.className` / `hosts` / `tls` | _(see values.yaml)_ | Ingress wiring. |
| `httpRoute.enabled` | `false` | Gateway API HTTPRoute (alternative to Ingress). |
| `resources` | requests `25m`/`64Mi`, limit `256Mi` | Container resources. |
| `livenessProbe` | `GET /healthz` | Liveness probe. |
| `readinessProbe` | `GET /readyz` | Readiness probe. |
| `startupProbe` | `GET /healthz`, 20×3s | Startup probe (guards slow first boot). |
| `autoscaling.enabled` | `false` | Render a HorizontalPodAutoscaler (`autoscaling/v2`) and leave `replicas` to it. Requires `state.driver=postgres`; fails the render on SQLite. |
| `autoscaling.minReplicas` / `maxReplicas` | `2` / `5` | HPA bounds. |
| `autoscaling.targetCPUUtilizationPercentage` / `targetMemoryUtilizationPercentage` | `80` / unset | HPA targets; at least one is required. |
| `podDisruptionBudget.enabled` | `false` | Render a PodDisruptionBudget. Useful with more than one replica. |
| `podDisruptionBudget.maxUnavailable` | `1` | PDB `maxUnavailable`. |
| `persistence.enabled` | `true` | Provision a PVC for the SQLite store. Ignored on Postgres. |
| `persistence.existingClaim` | `""` | Use an existing PVC instead. |
| `persistence.storageClass` | `""` | StorageClass (`""` = cluster default, `"-"` = none). |
| `persistence.accessMode` | `ReadWriteOnce` | PVC access mode. |
| `persistence.size` | `1Gi` | PVC size. |
| `persistence.annotations` | `{}` | Extra PVC annotations. |
| `state.driver` | `sqlite` | `STATE_DRIVER`: `sqlite` (one replica, PVC) or `postgres` (HA mode). |
| `state.mountPath` | `/var/lib/tempogate` | Where the PVC is mounted. |
| `state.sqlitePath` | `/var/lib/tempogate/state.db` | `STATE_SQLITE_PATH` (must be under `mountPath`). |
| `state.postgres.dsnSecretRef` | `{name,key}` empty | Secret holding the connection string; required with `state.driver=postgres`. Mounted as `STATE_POSTGRES_DSN_FILE` into serve and migrate. |
| `state.postgres.listenDsnSecretRef` | `{name,key}` empty | Secret holding `STATE_POSTGRES_LISTEN_DSN` (serve only). Empty uses the DSN. |
| `state.postgres.maxConns` | `0` | `STATE_POSTGRES_MAX_CONNS` per replica; `0` keeps the binary default (10). |
| `state.postgres.connMaxIdleTime` | `""` | `STATE_POSTGRES_CONN_MAX_IDLE_TIME`; empty keeps the binary default (30m). |
| `state.postgres.allowInsecureSslMode` | `false` | `STATE_POSTGRES_ALLOW_INSECURE_SSLMODE` - development only. |
| `log.level` | `info` | `LOG_LEVEL` (`debug`/`info`/`warn`/`error`). |
| `log.format` | `json` | `LOG_FORMAT` (`json`/`pretty`/`auto`). |
| `keys.encryptionKeySecretRef` | `{name,key}` empty | Secret holding `KEYS_ENCRYPTION_KEY` (base64 32-byte key that encrypts the stored signing key). Recommended in production; once set, tempogate needs it to boot. See [docs/hardening.md](../../docs/hardening.md#signing-key-encryption). |
| `oidc.issuer` | `""` | `OIDC_ISSUER` — externally reachable base URL. |
| `oidc.allowInsecureIssuer` | `false` | `OIDC_ALLOW_INSECURE_ISSUER` - development only. `serve` refuses a plain-http issuer on a non-loopback host unless this is `true`. |
| `oidc.sessionSigningKeySecretRef` | `{name,key}` empty | Secret holding `OIDC_SESSION_SIGNING_KEY` (base64url 32-byte HMAC key for the device-flow verification-page cookie). tempogate refuses to boot when unset. |
| `oidc.sessionTtl` | `""` | `OIDC_SESSION_TTL` — verification-page cookie TTL (Go duration). `""` leaves the binary default (5m). |
| `auth.clients` | `""` | `OIDC_CLIENTS` - `id:redirect_uri` allowlist of exact redirect URIs (loopback `http://127.0.0.1/<path>` matches any port; `id:` registers a device-only client). See [docs/configuration.md](../../docs/configuration.md#redirect-uri-registration). |
| `auth.allowInsecureRedirectUris` | `false` | `OIDC_ALLOW_INSECURE_REDIRECT_URIS` - dev only; allow plain-http non-loopback redirect URIs. |
| `auth.allowedDomains` | `[]` | `OIDC_ALLOWED_DOMAINS` — SSO email-domain gate. |
| `auth.allowedHostedDomains` | `[]` | `OIDC_ALLOWED_HOSTED_DOMAINS` - Google Workspace `hd` gate ("Workspace mode"); recommended for Workspace organizations. |
| `authz.rules` | `[]` | `OIDC_AUTHZ_RULES_<n>` - `"<selector>=<namespace>:<role>[,...]"` rules mapping `email:<address>` or `domain:<domain>` to Temporal permissions. See [docs/authorization.md](../../docs/authorization.md#authorization). |
| `authz.defaultPermissions` | `""` | `OIDC_AUTHZ_DEFAULT_PERMISSIONS` - permissions for admitted people no rule matches. Empty denies them. With `authz.rules` also empty, tempogate refuses to start; `temporal-system:admin` keeps the pre-rules behaviour (logged as a warning). |
| `auth.clientSecretsSecretRef` | `{name,key}` empty | Secret holding `OIDC_CLIENT_SECRETS`. |
| `auth.upstream.google.clientIdSecretRef` | `{name,key}` empty | Secret holding the Google client id. |
| `auth.upstream.google.clientSecretSecretRef` | `{name,key}` empty | Secret holding the Google client secret. |
| `auth.upstream.google.authEndpoint` / `tokenEndpoint` / `issuerUrl` | `""` | Upstream endpoint overrides (testing). |
| `admin.tokenSha256SecretRef` | `{name,key}` empty | Secret holding `ADMIN_TOKEN_SHA256` (hex SHA-256 digests of admin tokens). Unset locks the admin API. |
| `admin.allowedHosts` | `[]` | `ADMIN_ALLOWED_HOSTS`. Empty with `service.admin.enabled` allows the admin Service DNS names on its port plus loopback names on any port. |
| `admin.allowSystemGrants` | `false` | `ADMIN_ALLOW_SYSTEM_GRANTS`: allow cluster-wide `temporal-system` keys. |
| `extraEnv` | `[]` | Extra env vars (serve container and migrate initContainer). |
| `volumes` / `volumeMounts` | `[]` | Extra volumes, mounted into the serve container and the migrate initContainer (e.g. a Postgres CA bundle). |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Scheduling. |

## Uninstall

```bash
helm uninstall tempogate
# On SQLite the chart-managed PVC (state.db) goes with the release. Use
# persistence.existingClaim if you need state to survive an uninstall.
# A Postgres database is left untouched.
```
