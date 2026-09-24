# tempogate Helm chart

Drop-in OIDC provider and OAuth2 authorization server for self-hosted
[Temporal](https://temporal.io/). This chart deploys a single tempogate
instance backed by a SQLite state store on a PersistentVolumeClaim.

## Prerequisites

- Kubernetes >= 1.25
- Helm >= 3.8 (OCI support; the chart is also published as an OCI artifact)
- A default StorageClass (or set `persistence.storageClass` /
  `persistence.existingClaim`)

## Install

From the repo checkout:

```bash
helm install tempogate ./charts/tempogate \
  --values examples/kind/values.yaml
```

From the published OCI registry:

```bash
helm install tempogate oci://ghcr.io/onhotpath/charts/tempogate \
  --version 0.1.0
```

Verify:

```bash
kubectl rollout status deploy/tempogate
kubectl port-forward svc/tempogate 8000:8000 &
curl -fsS http://127.0.0.1:8000/healthz
```

## Architecture notes

- **Single replica, by design.** The default state store is SQLite on one
  ReadWriteOnce PVC, and SQLite allows exactly one writer. `replicaCount`
  MUST stay `1` and `autoscaling` MUST stay disabled until a shared state
  backend lands upstream. The Deployment uses the `Recreate` strategy so an
  update never runs two pods against the same volume.
- **Single HTTP port.** tempogate currently exposes one listener that
  serves the public OIDC/OAuth2 surface together with `/healthz` and
  `/readyz`. A dedicated admin listener is planned upstream; when it lands
  the chart gains a `service.admin` block — `service.port` does not change.
- **Schema migrations** run in a dedicated `tempogate migrate` Job
  applied alongside the release (not a Helm hook — Helm v4's sequential
  hook execution deadlocks a hook Job against a chart-managed
  `WaitForFirstConsumer` PVC). The migrate pod and the serve pod share
  the PVC; whichever the scheduler places first is the volume's first
  consumer, so the chart needs no special StorageClass. `serve` refuses
  to run against a stale store, so a serve pod that starts before the
  migration finishes exits and is restarted until the schema is current
  (seconds, on SQLite). The Job name carries the release revision so
  `helm upgrade` always runs a fresh migration.
- **State is release-managed.** The chart-managed PVC is removed on
  `helm uninstall` (signing keypair + refresh tokens included). To keep
  state across an uninstall, pre-create a PVC and set
  `persistence.existingClaim`.

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

## Values

| Key | Default | Description |
| --- | --- | --- |
| `replicaCount` | `1` | Pods. MUST stay `1` (SQLite single-writer). |
| `image.repository` | `ghcr.io/onhotpath/tempogate` | Image repository. |
| `image.tag` | `""` | Image tag; defaults to the chart `appVersion`. |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy. |
| `imagePullSecrets` | `[]` | Image pull secrets. |
| `nameOverride` / `fullnameOverride` | `""` | Name overrides. |
| `serviceAccount.create` | `true` | Create a ServiceAccount. |
| `serviceAccount.name` | `""` | ServiceAccount name (generated when empty). |
| `podAnnotations` / `podLabels` | `{}` | Extra pod metadata. |
| `podSecurityContext` | `runAsNonRoot`, uid/gid/fsGroup `65532` | Pod security context (matches the distroless `nonroot` user). |
| `securityContext` | drop ALL, no privilege escalation, read-only rootfs | Container security context. |
| `service.type` | `ClusterIP` | Service type. |
| `service.port` | `8000` | The single HTTP port (public + health). |
| `listenAddress` | `0.0.0.0` | `HTTP_LISTENER` bind host (must not be loopback in-cluster). |
| `ingress.enabled` | `false` | Enable Ingress. |
| `ingress.className` / `hosts` / `tls` | _(see values.yaml)_ | Ingress wiring. |
| `httpRoute.enabled` | `false` | Gateway API HTTPRoute (alternative to Ingress). |
| `resources` | requests `25m`/`64Mi`, limit `256Mi` | Container resources. |
| `livenessProbe` | `GET /healthz` | Liveness probe. |
| `readinessProbe` | `GET /readyz` | Readiness probe. |
| `startupProbe` | `GET /healthz`, 20×3s | Startup probe (guards slow first boot). |
| `autoscaling.enabled` | `false` | MUST stay disabled (single-writer). |
| `persistence.enabled` | `true` | Provision a PVC for the SQLite store. |
| `persistence.existingClaim` | `""` | Use an existing PVC instead. |
| `persistence.storageClass` | `""` | StorageClass (`""` = cluster default, `"-"` = none). |
| `persistence.accessMode` | `ReadWriteOnce` | PVC access mode. |
| `persistence.size` | `1Gi` | PVC size. |
| `persistence.annotations` | `{}` | Extra PVC annotations. |
| `state.mountPath` | `/var/lib/tempogate` | Where the PVC is mounted. |
| `state.sqlitePath` | `/var/lib/tempogate/state.db` | `STATE_SQLITE_PATH` (must be under `mountPath`). |
| `log.level` | `info` | `LOG_LEVEL` (`debug`/`info`/`warn`/`error`). |
| `oidc.issuer` | `""` | `OIDC_ISSUER` — externally reachable base URL. |
| `oidc.sessionSigningKeySecretRef` | `{name,key}` empty | Secret holding `OIDC_SESSION_SIGNING_KEY` (base64url 32-byte HMAC key for the device-flow verification-page cookie). tempogate refuses to boot when unset. |
| `oidc.sessionTtl` | `""` | `OIDC_SESSION_TTL` — verification-page cookie TTL (Go duration). `""` leaves the binary default (5m). |
| `auth.clients` | `""` | `OIDC_CLIENTS` — `id:redirect_uri_prefix` allowlist. |
| `auth.allowedDomains` | `[]` | `OIDC_ALLOWED_DOMAINS` — SSO email-domain gate. |
| `auth.clientSecretsSecretRef` | `{name,key}` empty | Secret holding `OIDC_CLIENT_SECRETS`. |
| `auth.upstream.google.clientIdSecretRef` | `{name,key}` empty | Secret holding the Google client id. |
| `auth.upstream.google.clientSecretSecretRef` | `{name,key}` empty | Secret holding the Google client secret. |
| `auth.upstream.google.authEndpoint` / `tokenEndpoint` / `issuerUrl` | `""` | Upstream endpoint overrides (testing). |
| `extraEnv` | `[]` | Extra env vars (Deployment). |
| `volumes` / `volumeMounts` | `[]` | Extra volumes/mounts. |
| `nodeSelector` / `tolerations` / `affinity` | `{}` / `[]` / `{}` | Scheduling. |

## Uninstall

```bash
helm uninstall tempogate
# the chart-managed PVC (state.db) goes with the release. Use
# persistence.existingClaim if you need state to survive an uninstall.
```
