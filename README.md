# tempogate

[![ci](https://github.com/onhotpath/tempogate/actions/workflows/ci.yml/badge.svg)](https://github.com/onhotpath/tempogate/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Go Reference](https://pkg.go.dev/badge/github.com/onhotpath/tempogate.svg)](https://pkg.go.dev/github.com/onhotpath/tempogate)
[![codecov](https://codecov.io/gh/onhotpath/tempogate/graph/badge.svg?token=6WiKK8pF1p)](https://codecov.io/gh/onhotpath/tempogate)

> A single-binary OIDC provider and OAuth2 authorization server that gives
> self-hosted [Temporal](https://temporal.io/) browser SSO and JWT machine-auth
> without forking `temporal-server` or running a sidecar proxy.

## Overview

Self-hosted Temporal can authenticate users and services, but only if you
supply an OIDC issuer. `tempogate` is that issuer. It federates sign-in to
Google, mints short-lived JWTs Temporal's stock authorizer already understands,
and publishes the JWKS the gRPC frontend verifies against. It runs as one
distroless binary and is aimed at teams operating their own Temporal cluster.

## Why it exists

Self-hosted Temporal ships two extension points:

- the **Web UI** consumes any OIDC issuer via `TEMPORAL_AUTH_*` env vars;
- the **gRPC frontend** verifies JWTs against a configurable JWKS endpoint and
  reads a `permissions: ["<namespace>:<action>", ...]` claim.

Together these cover SSO and machine-auth — but only if something issues the
tokens. The usual alternatives are forking `temporal-server` or putting a
reverse proxy in front of it; both carry ongoing cost (see
[the comparison below](#why-not-a-sidecar-proxy-or-a-fork)). `tempogate` fills
the gap Temporal's own docs already describe: point the Web UI at
`https://tempogate.<your-domain>` and the frontend's
`global.authorization.jwtKeyProvider.keySourceURIs` at
`https://tempogate.<your-domain>/.well-known/jwks.json`.

## How it works

```
┌──────────────┐     OIDC      ┌────────────────────┐
│ Temporal Web │ ─────────────▶│      tempogate     │ ──wraps──▶ Google OAuth2
│      UI      │◀── our JWT ───│  (OIDC + OAuth2 AS) │
└──────┬───────┘               └────────────────────┘
       │ Bearer <tempogate JWT>          ▲
       ▼                                 │
┌──────────────┐         JWKS            │
│  temporal-   │ ◀───────────────────────┘
│  frontend    │  (stock default JWT ClaimMapper)
└──────────────┘
```

One binary with subcommands `serve`, `login`, `token`, `keys`, `migrate`,
`version`. State is pluggable; the default is SQLite on a PVC via the pure-Go
`modernc.org/sqlite` driver, with embedded migrations applied by
`tempogate migrate`.

## Status

Wired and exercised end to end:

- `/healthz`, `/readyz`
- `/.well-known/jwks.json` and the full `/.well-known/openid-configuration`
- OIDC SSO: `/authorize`, `/callback/google`, `/token`, `/userinfo`
- `tempogate login` + `tempogate token` for personal tokens from a laptop
  (persisted `0600`, auto-refreshed near expiry)
- PKCE mandatory by default, with a narrow secret-gated carve-out for
  confidential clients such as the Temporal Web UI — see
  [docs/pkce-and-confidential-clients.md](docs/pkce-and-confidential-clients.md)
- OIDC Core `nonce` round-trip and `aud` stamping
- Multi-arch distroless image and a Helm chart

Authorization is currently flat: every admitted identity receives
cluster-level access (`temporal-system:admin`), the value Temporal's default
ClaimMapper needs for cluster APIs. Group- or role-derived per-namespace
scoping and an admin API for long-lived integration keys are planned.

### Revoking integration keys

`DELETE /admin/keys/:id` marks a key revoked and adds its `jti` to a
SQLite-backed denylist. The denylist is consulted by tempogate's *own*
verifier (refresh-token exchange, `/userinfo`) through a 30 s read-through
cache, so a revoke takes effect on those flows within 30 s on a single
instance, and is hydrated synchronously in-process for the instance that
served the DELETE.

Temporal's frontend, however, validates JWTs with its default
`ClaimMapper` against `/.well-known/jwks.json` only — it has no hook to
consult a per-issuer denylist. The practical consequence:

| Verification path                   | Time until revoke takes effect       |
| ----------------------------------- | ------------------------------------ |
| tempogate (refresh, `/userinfo`)    | up to **30 s** (denylist cache TTL)  |
| Temporal frontend gRPC              | up to the **token's `exp`** lifetime |

This is the acknowledged trade-off of stateless JWTs against Temporal's
stock verifier. Mint integration keys with a deliberately bounded `exp` if
your threat model needs an upper bound on revoke lag for Temporal gRPC; a
future move to opaque, server-introspected keys would close the gap
end-to-end.

New here? [docs/getting-started.md](docs/getting-started.md) takes you from
nothing to a working Web-UI SSO + CLI token in under ten minutes, with no
Google account required (a bundled mock IdP stands in).

## Multi-tenancy

Tempogate serializes a token's authorization as a flat `permissions` claim of
`"<namespace>:<role>"` entries — the exact shape Temporal's default JWT
`ClaimMapper` parses into `claims.Namespaces[ns] = role`. Two entries in the
array for **different** namespaces accumulate independently, so a single token
can grant `read` on one namespace and `admin` on another; two entries for the
**same** namespace last-write-wins, mirroring the ClaimMapper's own behaviour.

The four canonical Temporal roles — `read`, `write`, `worker`, `admin` —
are honoured verbatim. Cluster-wide access is expressed by granting a role on
the `temporal-system` namespace (the only construct the default ClaimMapper
recognises for "every namespace"); the literal `*` is rejected as a real
namespace name by the same authorizer, so the `perms.AddWildcard` Go-API
sugar is internally rewritten to `temporal-system:<role>` before serialization.
The model lives in the [`perms`](perms/perms.go) package; both the OIDC
`/token` flow and the `/admin/keys` admin API funnel through `perms.Grant`
so the wire shape stays uniform regardless of which path minted the token.

A token issued for `tenant-a` cannot perform any action on `tenant-b`. That
boundary is enforced at the Temporal frontend by the default authorizer — not
inside tempogate — and is the reference behaviour proved end-to-end in
[`test/e2e/multi_tenant_test.go`](test/e2e/multi_tenant_test.go), which
provisions two namespaces against a real `temporal-frontend` and asserts both
the cross-namespace denial (gRPC `PermissionDenied`) and the multi-namespace
accumulation (one token, two namespaces, different roles enforced
independently).

The `/admin/keys` admin API deliberately mints one (namespace, role) per key
so audit and rotation always reason over a minimal scope; a caller that needs
multi-namespace authorization issues several keys, or — for humans — picks up
the multi-ns shape automatically through the OIDC `/token` path as the
identity-mapping layer matures.

## Quick start

Run a published image:

```bash
TEMPOGATE_IMAGE=${TEMPOGATE_IMAGE:-ghcr.io/onhotpath/tempogate:latest}
export OIDC_SESSION_SIGNING_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1:8000/device/sso-callback'
export OIDC_CLIENT_SECRETS="tempogate-device-ui:$(openssl rand -hex 32)"
docker volume create tempogate-state
docker run --rm --mount source=tempogate-state,target=/var/lib/tempogate \
  -e OIDC_SESSION_SIGNING_KEY -e OIDC_CLIENTS -e OIDC_CLIENT_SECRETS \
  "$TEMPOGATE_IMAGE" migrate
docker run --rm -d --name tempogate -p 8000:8000 \
  --mount source=tempogate-state,target=/var/lib/tempogate \
  -e OIDC_SESSION_SIGNING_KEY -e OIDC_CLIENTS -e OIDC_CLIENT_SECRETS \
  -e HTTP_LISTENER=0.0.0.0:8000 "$TEMPOGATE_IMAGE"
curl --retry 20 --retry-delay 1 --retry-all-errors -fsS http://127.0.0.1:8000/healthz
```

Keep the signing key and SQLite volume across restarts. The generated client
secret is for this health-check example; configure `OIDC_ISSUER`, registered
clients, allowed domains, and Google credentials for real login. Save those
secrets outside the shell before using this as a lasting deployment. Stop the
example with `docker stop tempogate`.

Container images are published to `ghcr.io/onhotpath/tempogate`:

| Tag | Meaning |
| --- | --- |
| `:vX.Y.Z`, `:X.Y`, `:X`, `:latest` | Stable releases (pushed on `git tag vX.Y.Z`) |
| `:vX.Y.Z-rc.N` | Pre-releases (release candidates) |
| `:sha-<short>` | One-off builds dispatched manually from a specific commit |

### Prebuilt CLI binaries

Every stable release and release candidate also ships a standalone, **lean**
`tempogate` CLI — just `login`, `token`, and `version`, with none of the
server/SQLite/OIDC-issuer stack compiled in — as GitHub Release assets for
`linux` and `darwin` on `amd64`/`arm64`, alongside a `checksums.txt`. Stable
releases are published; release candidates are marked pre-release; manual
dispatch builds attach the binaries to the workflow run only.

On macOS, via the Homebrew tap (hosted in this repository):

```bash
brew tap onhotpath/tempogate https://github.com/onhotpath/tempogate
brew install tempogate
```

Or download a release asset directly (Linux x86_64 shown — pick your os/arch):

```bash
gh release download vX.Y.Z --repo onhotpath/tempogate \
  --pattern 'tempogate_*_linux_x86_64.tar.gz' --pattern checksums.txt
sha256sum -c --ignore-missing checksums.txt
tar -xzf tempogate_*_linux_x86_64.tar.gz
./tempogate version --detailed
```

Cutting a release? See [RELEASING.md](RELEASING.md).

Build from source:

```bash
git clone git@github.com:onhotpath/tempogate.git
cd tempogate
make build
export STATE_SQLITE_PATH="$PWD/state.db"
export OIDC_SESSION_SIGNING_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1:8000/device/sso-callback'
export OIDC_CLIENT_SECRETS="tempogate-device-ui:$(openssl rand -hex 32)"
./.bin/tempogate migrate
./.bin/tempogate serve            # listens on 127.0.0.1:8000
```

Or build the container locally:

```bash
docker build -t tempogate:dev .
TEMPOGATE_IMAGE=tempogate:dev    # then run the Quick start above
```

Kubernetes deployment is covered by the chart in
[`charts/tempogate/`](charts/tempogate/README.md). It is published as an
OCI artifact, so no repo clone is needed:

```bash
helm install tempogate oci://ghcr.io/onhotpath/charts/tempogate --version 0.1.0
```

The chart is versioned independently of the binary; pick the version from
the [chart releases](https://github.com/onhotpath/tempogate/releases?q=chart-v).

## Personal tokens from a laptop

Once the server is reachable, a user mints a short-lived Temporal JWT
without hand-editing any config:

```bash
export TEMPOGATE_ISSUER=https://tempogate.example.com

tempogate login                                  # browser sign-in, once
export TEMPORAL_AUTH_TOKEN=$(tempogate token)    # thereafter; auto-refreshes
```

`tempogate login` starts a one-shot `127.0.0.1` server, opens your browser to
sign in via Google, prints the token, and persists it to
`~/.tempogate/token.json` (`0600`). A fresh ephemeral loopback port is used
each run — no Google Cloud Console edits, just one `OIDC_CLIENTS` entry on the
server. `tempogate token` then reuses that file, refreshing the token five
minutes before expiry, so it never re-opens a browser. Both print only the
token to stdout, so they are safe in `$(...)`. See
[docs/cli-loopback-login.md](docs/cli-loopback-login.md) for persistence,
auto-refresh, the operator one-liner, and why ephemeral ports work.

For hosts without a browser (remote SSH sessions, cloud dev VMs, CI debug
shells), use `tempogate login --device` — the OAuth 2.0 device authorization
grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)); the CLI
prints a short code and a URL you open on any other device with a browser.
See [docs/cli-device-login.md](docs/cli-device-login.md).

## Configuration

Configuration is layered: defaults, then an optional `application.yaml`, then
environment variables (env wins). Nested keys flatten with `_` as the
separator.

| Env var | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | For real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer` and used to derive `jwks_uri`. May include a path (e.g. `https://host/idp`) — see [Sub-path hosting](#sub-path-hosting) |
| `OIDC_CLIENTS` | For any login | _(empty)_ | Comma-separated `id:redirect_uri_prefix` allowlist. Register the CLI as `tempogate-cli:http://127.0.0.1:` |
| `OIDC_ALLOWED_DOMAINS` | For any login | _(empty)_ | Comma-separated email-domain gate applied after Google sign-in |
| `OIDC_GOOGLE_CLIENT_ID` | For any login | _(empty)_ | Upstream Google OAuth client |
| `OIDC_GOOGLE_CLIENT_SECRET` | For any login | _(empty)_ | Upstream Google OAuth client secret |
| `OIDC_CLIENT_SECRETS` | No | _(empty)_ | Comma-separated `id:secret`; promotes a registered client to confidential (PKCE carve-out) |
| `HTTP_LISTENER` | No | `127.0.0.1:8000` | `host:port` for the public listener |
| `STATE_SQLITE_PATH` | No | `/var/lib/tempogate/state.db` | SQLite state-store path (back this with a PVC) |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error` |
| `TEMPOGATE_ISSUER` | No | _(empty)_ | **Client-side**, read by `tempogate login` (not the server). Equivalent to `--issuer` |

## Sub-path hosting

`OIDC_ISSUER` may contain a path, so tempogate can share a hostname with
another app instead of needing its own. Set the issuer to the full external
URL including the path, e.g.:

```
OIDC_ISSUER=https://tempogate.example.com/idp
```

tempogate then serves its **entire OIDC surface under that prefix** —
`/idp/.well-known/openid-configuration`, `/idp/.well-known/jwks.json`,
`/idp/authorize`, `/idp/token`, `/idp/userinfo`, `/idp/callback/google` — and
the discovery document advertises issuer-relative (prefixed) endpoints, so the
`iss` claim, the advertised endpoints, and the served routes stay in lockstep.
A root issuer (no path) behaves exactly as before.

Route a path prefix on the shared host to tempogate at your reverse proxy
(strip nothing — tempogate owns the prefix natively). Two operational notes:

- **Health probes stay at the root**: `/healthz` and `/readyz` are *not*
  moved under the prefix (they are infra probes, not part of the public OIDC
  surface). Point Kubernetes liveness/readiness at `/healthz` / `/readyz`
  regardless of the issuer path; you do not need to route them through the
  shared-host proxy.
- **Google authorized redirect URI** must match the prefixed callback:
  register `https://tempogate.example.com/idp/callback/google` (issuer +
  `/callback/google`) in the Google OAuth client.

## Why not a sidecar proxy or a fork?

| Approach | Pros | Cons |
| --- | --- | --- |
| **tempogate (OIDC + OAuth2 AS, this repo)** | Stateless integration with stock Temporal. No fork, no proxy. | A second component to operate. |
| Sidecar reverse-proxy in front of UI/gRPC | Auth logic outside Temporal. | Has to demux gRPC + HTTP; brittle around streaming; obscures Temporal's own auth machinery. |
| Forked `temporal-server` | Total control. | Permanent rebase tax; loses upstream support; defeats the "self-hosted but supported" posture. |

## Development

```bash
make tools         # install pinned gci + golangci-lint into ./.bin
make check         # fmt + vet + gci; fails on a dirty tree
make lint          # golangci-lint
make test          # check + race + coverage
make ci            # what GitHub Actions runs
make test-e2e      # container-backed acceptance proofs (needs Docker)
```

`make test-e2e` stands up `temporalio/ui`, a JWKS-backed `temporal-frontend`,
a mock Google IdP, and headless Chrome via testcontainers, and proves two
flows end to end: Web UI SSO login, and the `tempogate login` CLI loopback
flow. Both assert that the minted JWT authenticates a gRPC `ListNamespaces`
and that an unauthenticated call is rejected. It is behind a `//go:build e2e`
tag and a dedicated CI job, so the default `make ci` stays fast.

Go 1.27+ is required. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Documentation

- [docs/getting-started.md](docs/getting-started.md) — zero to working
  Web-UI SSO + CLI token in under ten minutes (bundled mock IdP)
- [docs/architecture.md](docs/architecture.md) — how the pieces fit and why
  it isn't a proxy or a fork
- [docs/configuration.md](docs/configuration.md) — every environment
  variable, with precedence and sub-path hosting
- [docs/cli-loopback-login.md](docs/cli-loopback-login.md) — the
  `tempogate login` loopback flow, persistence, and auto-refresh
- [docs/cli-device-login.md](docs/cli-device-login.md) — the
  `tempogate login --device` flow for hosts without a browser (RFC 8628)
- [docs/pkce-and-confidential-clients.md](docs/pkce-and-confidential-clients.md)
  — PKCE posture and the confidential-client carve-out
- [examples/docker-compose/](examples/docker-compose/README.md) — the full
  stack locally, one command
- [examples/kind/](examples/kind/README.md) — deploy to a local Kubernetes
  cluster via the chart
- [examples/google-oauth-setup.md](examples/google-oauth-setup.md) —
  create the upstream Google OAuth client
- [charts/tempogate/README.md](charts/tempogate/README.md) — Helm deployment

## Security

Report vulnerabilities via
[GitHub Security Advisories](https://github.com/onhotpath/tempogate/security/advisories/new)
— see [SECURITY.md](SECURITY.md). **Do not** open public issues for security
reports.

## License

Apache 2.0 — see [LICENSE](LICENSE).
