# docker-compose example

> [!CAUTION]
> **DEV ONLY. Never expose this stack to a network.**
> The bundled mock IdP signs in **anyone who can reach it as any identity**, and the demo identity gets full Temporal access.
> Every port is published on `127.0.0.1` only, and the secrets have no defaults: you generate them locally with `./gen-env.sh`.
> Do not change the port bindings to `0.0.0.0`, and do not reuse the generated secrets anywhere else.

A full Temporal cluster whose **Web UI signs in through tempogate** and whose
**gRPC frontend verifies tempogate-minted JWTs** — with a bundled mock IdP, so
it proves the whole chain end to end with **no Google account and no config**.

## Make it go

```bash
echo "127.0.0.1 tempogate temporal-ui mockoidc" | sudo tee -a /etc/hosts   # one time
cd examples/docker-compose
./gen-env.sh > .env                     # fresh random secrets, one time
docker compose up --build
# wait for "Temporal server started", then open:
open http://temporal-ui:8080            # Linux: xdg-open
```

Click **Sign in**, approve on the mock consent screen (it asserts
`alice@example.com`), and you land in the Temporal UI authenticated by a JWT
tempogate issued. `curl -fsS http://tempogate:8000/healthz` returns `200`.

The API docs are on too: browse the OIDC endpoints at
<http://tempogate:8000/docs> (the raw spec is
<http://tempogate:8000/openapi.json>). `API_DOCS_ENABLED` is for local stacks
like this one only: `serve` refuses it unless `OIDC_ISSUER` is plain `http://`,
and the admin listener never serves docs. Elsewhere, use `tempogate gen-oas`
(add `--admin` for the admin API).

Without a `.env`, `docker compose` refuses to start and names the missing
secret (`required variable TEMPOGATE_SESSION_SIGNING_KEY is missing a value`).

> During first boot the `temporal` container logs two one-shot
> `ERROR ... Namespace default is not found` lines — that is
> `temporalio/auto-setup`'s own probe-before-create, immediately followed by
> "Default namespace default registration complete". It is expected and not
> an auth failure. (auto-setup provisions over the auth-exempt internal
> frontend; see the `temporal:` comment in `docker-compose.yml`.)

Tear down (volume included):

```bash
docker compose down -v
rm .env
sudo sed -i.bak '\#127\.0\.0\.1 tempogate temporal-ui mockoidc#d' /etc/hosts
```

## Why the /etc/hosts line

`tempogate`, `temporal-ui`, and `mockoidc` each appear in **both** a browser
redirect (must resolve on your machine) **and** a server-to-server call (must
resolve container-to-container). One name has to mean the same thing in both
places. Mapping the three to `127.0.0.1` does that: your browser reaches the
published `127.0.0.1` ports, and Docker's own DNS still resolves them between containers.
It is the exact hostname scheme `test/e2e/web_ui_sso_test.go` proves works.

### Linux: skip the edit

On Linux you can put every container in the host network namespace instead:

```bash
docker compose -f docker-compose.yml -f docker-compose.host-network.yml up --build
# everything is on localhost: http://localhost:8080 (API docs: http://localhost:8000/docs)
```

Host networking bypasses Docker's port publishing, so the overlay pins each
listener to `127.0.0.1` itself. The exception is `temporal-ui`: its image has
no bind-address setting and listens on all interfaces, so block port `8080`
with a host firewall if the machine is reachable from a network.

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

`docker compose` reads `.env` from this directory. The secrets have no
defaults, so `./gen-env.sh > .env` is required; each value is a one-liner if
you prefer to write the file by hand:

| Variable | Generate with |
| --- | --- |
| `TEMPOGATE_SESSION_SIGNING_KEY` | `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='` |
| `TEMPORAL_UI_CLIENT_SECRET` | `openssl rand -hex 32` |
| `TEMPOGATE_DEVICE_UI_CLIENT_SECRET` | `openssl rand -hex 32` |
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` |

Optional, non-secret knobs: `DEMO_EMAIL` (the identity the mock asserts,
default `alice@example.com`), `TEMPOGATE_ALLOWED_DOMAINS` (default
`example.com`), `LOG_LEVEL` (default `info`), and `LOG_FORMAT` (default
`json`; `pretty` for reading `docker compose logs` by eye). Full env-var reference:
[`docs/configuration.md`](../../docs/configuration.md).

## Who gets access

tempogate denies by default: a signed-in person gets the Temporal permissions their authorization rules grant, and nothing else.
The compose file grants the demo identity (`DEMO_EMAIL`) cluster admin with one rule:

```yaml
OIDC_AUTHZ_RULES_0: "email:${DEMO_EMAIL:-alice@example.com}=temporal-system:admin"
```

To try a narrower grant, add rules to the `tempogate` service and restart it, e.g. `OIDC_AUTHZ_RULES_1: "email:bob@example.com=default:read"`, then sign in as bob with `DEMO_EMAIL=bob@example.com docker compose up -d`.
An identity no rule matches is refused at sign-in with `access_denied`.
See [Authorization](../../docs/authorization.md#authorization).

## Next

- The interactive walkthrough with the CLI token step:
  [`docs/getting-started.md`](../../docs/getting-started.md)
- Point tempogate at a **real** Google client:
  [`examples/google-oauth-setup.md`](../google-oauth-setup.md)
- Deploy to a cluster: [`examples/kind/`](../kind/README.md) and the
  [Helm chart](../../charts/tempogate/README.md)
