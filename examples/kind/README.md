# kind example

Deploy the tempogate Helm chart to a local [kind](https://kind.sigs.k8s.io/)
cluster from a fresh checkout — no published image, no ingress, no DNS.

## Make it go

```bash
cd examples/kind
bash bootstrap.sh
```

`bootstrap.sh` creates a kind cluster (if absent), builds the image, loads it
into the node, creates the `tempogate-kind` Secret (a random session signing
key and `tempogate-device-ui` client secret, which `serve` requires),
installs the chart with `values.yaml`, waits for rollout, and proves
`/healthz` returns `200`. It is idempotent - re-run to upgrade.

Then reach the server yourself:

```bash
kubectl port-forward svc/tempogate 8000:8000
curl http://127.0.0.1:8000/healthz
```

Tear down:

```bash
kind delete cluster --name tempogate-demo
```

Overrides via env: `CLUSTER`, `RELEASE`.

## What this proves (and what it doesn't)

`values.yaml` is a **smoke overlay**: small resource requests, the cluster's
default StorageClass for the SQLite PVC, debug logging, and an issuer of
`http://127.0.0.1:8000` reachable over `kubectl port-forward`. It proves the
chart installs, the migrate Job runs, and the server serves `/healthz`.

It does **not** wire SSO — no upstream Google client is configured, so the
login flow is not exercised here. The full interactive SSO + CLI-token story
is the docker-compose example and the getting-started guide.

## Going further

- **Real Google SSO:** create an upstream client
  ([`../google-oauth-setup.md`](../google-oauth-setup.md)), put its
  credentials in a Secret, and set `oidc.issuer`, `auth.clients`,
  `auth.allowedDomains`, and the Google `*SecretRef` chart values — see the
  [chart README](../../charts/tempogate/README.md).
- **Point Temporal at tempogate's JWKS:**
  [`temporal-values.yaml`](./temporal-values.yaml) — both the Temporal Helm
  chart form and the auto-setup env form.
- **End-to-end walkthrough:**
  [`../../docs/getting-started.md`](../../docs/getting-started.md).
