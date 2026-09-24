# Getting started

From nothing to a working Temporal Web UI SSO **and** a CLI token, in under
ten minutes, on one machine.

## What is tempogate?

Self-hosted Temporal can authenticate users and services, but only if you
supply an OIDC issuer — it ships the extension points and none of the issuer.
tempogate is that issuer: a single binary that federates sign-in to Google,
mints the short-lived JWTs Temporal's stock authorizer already understands,
and publishes the JWKS the gRPC frontend verifies against. No `temporal-server`
fork, no sidecar proxy.

## Prerequisites

For this walkthrough: **only [Docker](https://docs.docker.com/get-docker/)**
(with `docker compose`). The example bundles a mock upstream IdP, so you need
**no Google account and no configuration** to see the whole chain work.

A real deployment swaps the mock for a Google OAuth client — that is a
separate ~5-minute task, [`examples/google-oauth-setup.md`](../examples/google-oauth-setup.md),
not needed here.

## 1. Run it locally

One hostname-resolution line (explained in the
[example README](../examples/docker-compose/README.md#why-the-etchosts-line)),
then one command:

```bash
echo "127.0.0.1 tempogate temporal-ui mockoidc" | sudo tee -a /etc/hosts
git clone https://github.com/onhotpath/tempogate.git
cd tempogate/examples/docker-compose
docker compose up --build
```

First run builds tempogate and the mock from source (a few minutes); wait for
`Temporal server started`. Sanity check from another shell:

```bash
curl -fsS http://tempogate:8000/healthz      # -> 200
```

> Linux and prefer no `/etc/hosts` edit? Use the host-network overlay — see
> the [example README](../examples/docker-compose/README.md#linux-skip-the-edit).

## 2. Log in via the Web UI

Open **http://temporal-ui:8080** and click **Sign in**.

![Temporal UI sign-in](img/getting-started/01-ui-signin.png)

You are redirected through tempogate to the mock IdP's one-click consent
screen. Click **Approve** (it asserts `alice@example.com`, whose domain is in
the demo's allowed list).

![Mock IdP consent screen](img/getting-started/02-consent.png)

You land back in the Temporal UI, **authenticated** — namespaces load. The
session is carrying a JWT tempogate minted; the Temporal frontend accepted it
by verifying it against tempogate's JWKS, with no Temporal-side custom code.

![Authenticated Temporal UI](img/getting-started/03-authenticated.png)

To see the rejection path, set `DEMO_EMAIL` to an out-of-domain address in
`.env` (`cp .env.example .env`), `docker compose up -d`, and sign in again:
tempogate returns a 403 "not in an allowed domain" instead of a token.

## 3. Get a CLI token

Machine and laptop access uses the same issuer, no browser kept open. Install
the lean CLI (macOS shown; Linux: download the release asset, or `make build`
from a checkout):

```bash
brew tap onhotpath/tempogate https://github.com/onhotpath/tempogate
brew install tempogate
```

Point it at the demo issuer and sign in once:

```bash
export TEMPOGATE__ISSUER=http://tempogate:8000
tempogate login                                  # browser sign-in, once
export TEMPORAL_AUTH_TOKEN=$(tempogate token)    # thereafter; auto-refreshes
```

`tempogate login` opens the same SSO flow on an ephemeral `127.0.0.1` port
(pre-registered as the `tempogate-cli` client in the example), prints the
token, and persists it `0600` to `~/.tempogate/token.json`. `tempogate token`
reuses that file, refreshing ~5 min before expiry, and prints only the token —
safe in `$(...)`. Details:
[`docs/cli-loopback-login.md`](cli-loopback-login.md).

> **No local browser?** On a remote SSH session, a cloud dev VM, or any host
> where the shell running `tempogate login` cannot open your browser, use the
> device-code flow instead:
>
> ```bash
> tempogate login --device
> ```
>
> The CLI prints a short code and a URL you open on any device with a
> browser — phone, laptop, tablet. Full UX in
> [`docs/cli-device-login.md`](cli-device-login.md).

```bash
tctl --address tempogate:7233 \
  --tls_server_name temporal \
  namespace list      # authenticated by the tempogate JWT in TEMPORAL_AUTH_TOKEN
```

## 4. Integration keys (planned)

Long-lived, revocable keys for unattended workers — minted by an operator and
exchanged for short JWTs without any browser — are a planned admin API
(`/admin/keys`) and a planned `service.admin` block in the chart. They are
**not in this release**; today's machine-auth path is the CLI token above
(short-lived, auto-refreshed). This section will gain the concrete steps when
the admin API ships; nothing in the example depends on it.

## Where to next

- **Real Google SSO:** [`examples/google-oauth-setup.md`](../examples/google-oauth-setup.md)
- **Deploy to a cluster:** [`examples/kind/`](../examples/kind/README.md) for
  local Kubernetes, then the [Helm chart](../charts/tempogate/README.md)
  (also published as an OCI artifact) for a real one
- **Configuration:** every env var, with precedence and sub-path hosting —
  [`docs/configuration.md`](configuration.md)
- **Architecture:** how the pieces fit and why it isn't a proxy or a fork —
  [`docs/architecture.md`](architecture.md)
- **Contributing:** [`CONTRIBUTING.md`](../CONTRIBUTING.md)

If a step took longer than it should have, that is a documentation bug —
please [open an issue](https://github.com/onhotpath/tempogate/issues).
