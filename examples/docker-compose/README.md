# docker-compose example

A full Temporal cluster whose **Web UI signs in through tempogate** and whose
**gRPC frontend verifies tempogate-minted JWTs** — with a bundled mock IdP, so
it proves the whole chain end to end with **no Google account and no config**.

## Make it go

```bash
echo "127.0.0.1 tempogate temporal-ui mockoidc" | sudo tee -a /etc/hosts   # one time
cd examples/docker-compose
docker compose up --build
# wait for "Temporal server started", then open:
open http://temporal-ui:8080            # Linux: xdg-open
```

Click **Sign in**, approve on the mock consent screen (it asserts
`alice@example.com`), and you land in the Temporal UI authenticated by a JWT
tempogate issued. `curl -fsS http://tempogate:8000/healthz` returns `200`.

> During first boot the `temporal` container logs two one-shot
> `ERROR ... Namespace default is not found` lines — that is
> `temporalio/auto-setup`'s own probe-before-create, immediately followed by
> "Default namespace default registration complete". It is expected and not
> an auth failure. (auto-setup provisions over the auth-exempt internal
> frontend; see the `temporal:` comment in `docker-compose.yml`.)

Tear down (volume included):

```bash
docker compose down -v
sudo sed -i.bak '\#127\.0\.0\.1 tempogate temporal-ui mockoidc#d' /etc/hosts
```

## Why the /etc/hosts line

`tempogate`, `temporal-ui`, and `mockoidc` each appear in **both** a browser
redirect (must resolve on your machine) **and** a server-to-server call (must
resolve container-to-container). One name has to mean the same thing in both
places. Mapping the three to `127.0.0.1` does that: your browser reaches the
published ports, and Docker's own DNS still resolves them between containers.
It is the exact hostname scheme `test/e2e/web_ui_sso_test.go` proves works.

### Linux: skip the edit

On Linux you can put every container in the host network namespace instead:

```bash
docker compose -f docker-compose.yml -f docker-compose.host-network.yml up --build
# everything is on localhost: http://localhost:8080
```

This is **Linux only** — on Docker Desktop (macOS/Windows) `network_mode:
host` binds the internal Linux VM, not your machine, and the mismatch returns.
See the header of `docker-compose.host-network.yml`.

## What's in the stack

| Service | Image | Role |
| --- | --- | --- |
| `mockoidc` | built from `test/e2e/mockgoogle` | Stand-in upstream IdP (real, tiny OIDC server) — plays Google's role |
| `tempogate-migrate` | built from repo `Dockerfile` | One-shot schema migration; exits before `serve` starts |
| `tempogate` | built from repo `Dockerfile` | The OIDC provider + OAuth2 AS under test |
| `db` | `postgres:16-alpine` | Temporal's datastore |
| `temporal` | `temporalio/auto-setup:1.25.2` | Temporal, **stock** JWT authorizer pointed at tempogate's JWKS |
| `temporal-ui` | `temporalio/ui:2.32.0` | Web UI, configured only via stock `TEMPORAL_AUTH_*` |

To run a published image instead of building tempogate from source, swap the
`build:` block for `image: ghcr.io/onhotpath/tempogate:latest` (commented in
`docker-compose.yml`).

## Configuration

Defaults work out of the box. To change the allowed email domain, the demo
identity, or the Web UI client secret, copy `.env.example` to `.env` and edit
— `docker compose` picks it up automatically. Full env-var reference:
[`docs/configuration.md`](../../docs/configuration.md).

## Next

- The interactive walkthrough with the CLI token step:
  [`docs/getting-started.md`](../../docs/getting-started.md)
- Point tempogate at a **real** Google client:
  [`examples/google-oauth-setup.md`](../google-oauth-setup.md)
- Deploy to a cluster: [`examples/kind/`](../kind/README.md) and the
  [Helm chart](../../charts/tempogate/README.md)
