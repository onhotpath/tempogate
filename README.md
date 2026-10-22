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

One binary with subcommands `serve`, `login`, `token`, `keys`, `sessions`,
`migrate`, `version`. State is pluggable; the default is SQLite on a PVC via the pure-Go
`modernc.org/sqlite` driver, with embedded migrations applied by
`tempogate migrate`.
`tempogate gen-oas` prints the OpenAPI 3.1 spec of the public API (`--admin` for the admin API, `-f json` for JSON).
`make gen-oas` writes both to `api/openapi.yaml` and `api/openapi.admin.yaml`; they are generated on demand and not committed.

## Status

Wired and exercised end to end:

- `/healthz`, `/readyz` (readiness also checks the SQLite state store)
- Prometheus `/metrics` on the private admin listener, and one structured
  access-log line per request (see [docs/configuration.md](docs/configuration.md#observability))
- `/.well-known/jwks.json` and the full `/.well-known/openid-configuration`
- OIDC SSO: `/authorize`, `/callback/google`, `/token`, `/userinfo`
- `tempogate login` + `tempogate token` for personal tokens from a laptop
  (persisted `0600`, auto-refreshed near expiry)
- PKCE mandatory by default, with a narrow secret-gated carve-out for
  confidential clients such as the Temporal Web UI — see
  [docs/pkce-and-confidential-clients.md](docs/pkce-and-confidential-clients.md)
- Separate access and ID tokens: the access token carries the Temporal
  audience and `permissions`; the ID token (`aud` = client, OIDC `nonce`)
  grants nothing at Temporal
- Multi-arch distroless image and a Helm chart

Authorization is currently flat: every admitted identity receives
cluster-level access (`temporal-system:admin`), the value Temporal's default
ClaimMapper needs for cluster APIs. Group- or role-derived per-namespace
scoping is planned; long-lived integration keys come from the admin API below.

### Integration keys (admin API)

`POST /admin/keys` mints a JWT for one (namespace, role) on a separate admin listener (`ADMIN_LISTENER`, default `127.0.0.1:8081`).
`expires_at` is required and may be at most `ADMIN_KEYS_MAX_TTL` (default 90 days) away.
Every `/admin/*` route except `/admin/healthz` needs a bearer admin token whose SHA-256 is listed in `ADMIN_TOKEN_SHA256`; with none configured the admin API is locked (401).
Requests whose `Host` is not in `ADMIN_ALLOWED_HOSTS` get 421, and `temporal-system` (cluster-wide) grants get 403 unless `ADMIN_ALLOW_SYSTEM_GRANTS=true`.
Every mint and revoke is written to an `admin audit` log line.

```bash
token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
export ADMIN_TOKEN_SHA256=$(printf %s "$token" | sha256sum | cut -d' ' -f1)
# after starting tempogate serve:
curl -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"namespace":"payments","role":"write","owner":"svc-payments","expires_at":"2026-12-31T00:00:00Z"}' \
  http://127.0.0.1:8081/admin/keys
```

See [docs/configuration.md](docs/configuration.md#admin-api) for all the settings.

### Revoking integration keys and retiring signing keys

`DELETE /admin/keys/:id` marks a key revoked and adds its `jti` to a
SQLite-backed denylist. The denylist is consulted by tempogate's *own*
verifier (`/userinfo`) through a 30 s read-through cache, so a revoke takes
effect there within 30 s on a single instance, and is hydrated synchronously
in-process for the instance that served the DELETE.
The denylist is not consulted by the refresh-token grant: refresh tokens are
opaque and have their own lifecycle (see [Sessions and refresh tokens](#sessions-and-refresh-tokens)).

Temporal's frontend, however, validates JWTs against
`/.well-known/jwks.json` and their `exp` only; it never sees the denylist.
The practical consequence:

| Verification path                   | Revoke takes effect                  |
| ----------------------------------- | ------------------------------------ |
| tempogate (`/userinfo`)             | within **30 s** (denylist cache TTL) |
| Temporal frontend gRPC              | only at the **token's `exp`**        |

That is why every integration key must carry an `exp`. The hard kill switch
is retiring the signing key: `tempogate keys retire <kid>` (or
`POST /admin/signing-keys/<kid>/retire`) stops it signing at once, and after
`KEYS_RETIREMENT_GRACE` (default 4 h) it leaves JWKS, so every token it signed
stops verifying at tempogate and, after its next JWKS refresh, at Temporal.
Rotate first with `tempogate keys generate --force`: a running server
publishes the new key within `KEYS_RELOAD_INTERVAL` (default 30 s) and signs
with it once `KEYS_PUBLISH_DELAY` (default 5 m, longer than Temporal's JWKS
refresh) has passed, no restart needed.
See the [rotation runbook](docs/configuration.md#rotation-runbook).
A future move to short-lived tokens exchanged from an opaque key would make
revocation effective at Temporal without retiring a key.

### Sessions and refresh tokens

A sign-in (Web UI SSO, `tempogate login`, or the device flow) starts a
session: a chain of single-use refresh tokens, each rotated on use.
Every refresh is governed by:

- **Idle lifetime** (`OIDC_REFRESH_TOKEN_TTL`, default 7 days): a session not refreshed for this long ends.
- **Absolute lifetime** (`OIDC_REFRESH_MAX_LIFETIME`, default 30 days): counted from the original sign-in and never extended by rotation, so every user goes back through Google at least this often.
- **Domain re-check**: `OIDC_ALLOWED_DOMAINS` is re-applied on every refresh. Removing a domain ends its users' sessions at their next refresh.
- **Reuse detection** ([RFC 9700 §4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)): presenting an already-rotated refresh token revokes the whole session, including the newer token, and logs a `refresh_token_reuse` warning with the session's family id, client and email (never the token).
  Two concurrent refreshes of the same token count as reuse too, so the loser's session ends and it signs in again.
- **Operator revocation**: `tempogate sessions list [--email <e>]` shows live sessions (never token values); `tempogate sessions revoke --email <e>` ends every session of a user and `--family <id>` ends one.
  Run them where the state volume is mounted, e.g. `kubectl exec deploy/tempogate -- /tempogate sessions revoke --email alice@example.com`.

Revocation stops refreshes; access tokens already issued stay valid at the Temporal frontend until they expire (`OIDC_ACCESS_TOKEN_TTL`, default 4 hours).
Lower it if you need a shorter revoke lag.

New here? [docs/getting-started.md](docs/getting-started.md) takes you from
nothing to a working Web-UI SSO + CLI token in under ten minutes, with no
Google account required (a bundled mock IdP stands in).

## Multi-tenancy

Tempogate serializes a token's authorization as a flat `permissions` claim of
`"<namespace>:<role>"` entries, the shape Temporal's default JWT `ClaimMapper` parses into a per-namespace role bitmask.
Two entries for **different** namespaces accumulate independently, so a single token can grant `read` on one namespace and `admin` on another.
Two entries for the **same** namespace are ORed together by the ClaimMapper, not overridden ([`default_jwt_claim_mapper.go`](https://github.com/temporalio/temporal/blob/v1.25.2/common/authorization/default_jwt_claim_mapper.go#L102-L127) in Temporal v1.25.2), so `ns:admin` plus `ns:read` authorizes admin.
Tempogate itself never emits duplicates: `perms.Grant` keeps one role per namespace.

The four canonical Temporal roles (`read`, `write`, `worker`, `admin`) are passed through verbatim.
`worker` on its own authorizes nothing: in Temporal's role bitmask it sits below `read`, and the default authorizer requires at least `read` for every API except health checks (task-queue polling is a write API).
Grant `write` to a namespace's workers.
Cluster-wide access is expressed by granting a role on
the `temporal-system` namespace (the only construct the default ClaimMapper
recognises for "every namespace"); the literal `*` is rejected as a real
namespace name by the same authorizer, so the `perms.AddWildcard` Go-API
sugar is internally rewritten to `temporal-system:<role>` before serialization.
The model lives in the [`perms`](perms/perms.go) package.
The `/admin/keys` admin API builds its claim through `perms.Grant`.
The OIDC `/token` flow does not use `perms.Grant` yet: it stamps the literal `temporal-system:admin` (see [flat authorization](#status)), which has the same wire shape.

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
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1/device/sso-callback'
export OIDC_CLIENT_SECRETS="tempogate-device-ui:$(openssl rand -hex 32)"
docker volume create tempogate-state
docker run --rm --mount source=tempogate-state,target=/var/lib/tempogate \
  "$TEMPOGATE_IMAGE" migrate
docker run --rm -d --name tempogate -p 127.0.0.1:8000:8000 \
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
| `:sha-<short>` | One-off builds dispatched manually from `main` or a `v*` tag, named after the built commit |

Every pushed image carries SLSA provenance and an SBOM attestation and is signed with cosign (keyless); [RELEASING.md](RELEASING.md#verify-a-release) shows how to verify them.

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
brew trust --cask onhotpath/tempogate/tempogate
brew install --cask tempogate
```

Homebrew 6 requires trust for casks from non-official taps.
The `brew trust` step grants trust only to the tempogate cask and is needed once.

The macOS binary is not signed or notarized by Apple: the project has no paid Apple Developer account.
So that Gatekeeper does not block it, the cask removes the `com.apple.quarantine` attribute after install, which also means Gatekeeper never checks the binary.
What you rely on instead is Homebrew's sha256 check of the release archive, which the cask pins, and the cosign-signed `checksums.txt` on the GitHub Release ([verify it](RELEASING.md#verify-a-release)).
If that is not acceptable for your machines, download the archive and verify the signature yourself, or build from source.

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
export OIDC_CLIENTS='tempogate-device-ui:http://127.0.0.1/device/sso-callback'
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
helm install tempogate oci://ghcr.io/onhotpath/charts/tempogate --version 0.3.0
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

The issuer must be `https://`, or plain `http://` on a loopback host.
For a plain-http development stack on another host, pass `--insecure` to `login` and `token`.
`tempogate token` is safe to run concurrently (e.g. as a credential helper): a lock on `<token-file>.lock` lets one process refresh while the others wait and reuse its token.

For hosts without a browser (remote SSH sessions, cloud dev VMs, CI debug
shells), use `tempogate login --device` — the OAuth 2.0 device authorization
grant ([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)); the CLI
prints a short code and a URL you open on any other device with a browser.
See [docs/cli-device-login.md](docs/cli-device-login.md).

## Configuration

Configuration is layered: defaults, then an optional yaml file, then
environment variables (env wins). Nested keys flatten with `_` as the
separator.
The yaml file is `--config <path>` (or `$TEMPOGATE_CONFIG`) when given, else
`application.yaml` in the working directory; parent directories are not
searched.
See [docs/configuration.md](docs/configuration.md).

| Env var | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | For real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer` and used to derive `jwks_uri`. Must be `https://` unless the host is loopback (see `OIDC_ALLOW_INSECURE_ISSUER`). May include a path (e.g. `https://host/idp`) - see [Sub-path hosting](#sub-path-hosting) |
| `OIDC_ALLOW_INSECURE_ISSUER` | No | `false` | Development only. `serve` refuses a plain-http `OIDC_ISSUER` unless its host is loopback (`localhost`, `127.0.0.0/8`, `::1`) or this is `true` |
| `OIDC_CLIENTS` | For any login | _(empty)_ | Comma-separated `id:redirect_uri` allowlist of **exact** redirect URIs (repeat an id for several). Loopback `http://127.0.0.1/<path>` entries match any port. Register the CLI as `tempogate-cli:http://127.0.0.1/callback` and the device CLI as `tempogate-device:` |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | No | `false` | Dev only: allow plain-`http` non-loopback redirect URIs in `OIDC_CLIENTS` (e.g. a local Docker Compose stack) |
| `OIDC_ALLOWED_DOMAINS` | For any login | _(empty)_ | Comma-separated email-domain gate applied after Google sign-in and again on every refresh |
| `OIDC_ALLOWED_HOSTED_DOMAINS` | Recommended | _(empty)_ | Comma-separated Google Workspace domains; when set, Google's `hd` claim must match ("Workspace mode"). See [docs/configuration.md](docs/configuration.md#hosted-domain-workspace-mode) |
| `OIDC_ACCESS_TOKEN_TTL` | No | `4h` | Lifetime of each access token (ID tokens live 5 minutes) |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | No | `temporal` | `aud` of every access token and integration key; set Temporal's `global.authorization.audience` (v1.29.0+) to match. See [Access tokens and ID tokens](docs/configuration.md#access-tokens-and-id-tokens) |
| `OIDC_REFRESH_TOKEN_TTL` | No | `168h` (7 days) | Idle lifetime of each rotated refresh token |
| `OIDC_REFRESH_MAX_LIFETIME` | No | `720h` (30 days) | Absolute session lifetime from sign-in; rotation never extends it. See [Sessions and refresh tokens](#sessions-and-refresh-tokens) |
| `OIDC_GOOGLE_CLIENT_ID` | For any login | _(empty)_ | Upstream Google OAuth client |
| `OIDC_GOOGLE_CLIENT_SECRET` | For any login | _(empty)_ | Upstream Google OAuth client secret |
| `OIDC_SESSION_SIGNING_KEY` | Yes | _(empty)_ | Base64url 32-byte HMAC key for the device-flow session cookie and SSO `state`, and for deriving the Google leg's PKCE verifier, nonce and browser binding; `serve` refuses to boot without it |
| `OIDC_SESSION_TTL` | No | `5m` | Lifetime of the device-flow verification-page session cookie |
| `OIDC_GOOGLE_AUTH_ENDPOINT`, `OIDC_GOOGLE_TOKEN_ENDPOINT`, `OIDC_GOOGLE_ISSUER_URL` | No | Google's | Upstream endpoint overrides, for a mock IdP only |
| `OIDC_CLIENT_SECRETS` | No | _(empty)_ | Comma-separated `id:secret`; promotes a registered client to confidential (PKCE carve-out) |
| `HTTP_LISTENER` | No | `127.0.0.1:8000` | `host:port` for the public listener |
| `HTTP_TRUSTED_PROXIES` | Behind a reverse proxy | _(empty)_ | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` is trusted for the client address. See [Abuse controls](docs/configuration.md#abuse-controls) |
| `HTTP_RATE_LIMIT_AUTHORIZE`, `HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION`, `HTTP_RATE_LIMIT_DEVICE_VERIFICATION`, `HTTP_RATE_LIMIT_TOKEN` | No | `30`, `10`, `20`, `60` | Requests per minute per client address to `/authorize`, `/device_authorization`, `POST /device` and `/token`; `0` disables |
| `API_DOCS_ENABLED` | No | `false` | Dev only: serve the OpenAPI document and docs page on the public listener. `serve` refuses it unless `OIDC_ISSUER` is plain `http://` |
| `ADMIN_LISTENER` | No | `127.0.0.1:8081` | `host:port` for the separate admin listener (`/admin/*`, Prometheus `/metrics`); never expose it publicly |
| `ADMIN_TOKEN_SHA256` | To use the admin API | _(empty)_ | Comma-separated hex SHA-256 digests of accepted admin bearer tokens. Empty locks the admin API (401) |
| `ADMIN_ALLOWED_HOSTS` | For a non-loopback admin bind | loopback names on the `ADMIN_LISTENER` port | Comma-separated `host[:port]` accepted in `Host`; others get 421 (DNS-rebinding defence) |
| `ADMIN_ALLOW_SYSTEM_GRANTS` | No | `false` | Allow minting cluster-wide `temporal-system` keys (403 otherwise) |
| `ADMIN_KEYS_MAX_TTL` | No | `2160h` (90 days) | Furthest in the future an integration key's required `expires_at` may lie |
| `SERVER_READ_HEADER_TIMEOUT`, `SERVER_READ_TIMEOUT`, `SERVER_WRITE_TIMEOUT`, `SERVER_IDLE_TIMEOUT`, `SERVER_MAX_HEADER_BYTES`, `SERVER_SHUTDOWN_TIMEOUT` | No | `10s`, `15s`, `30s`, `60s`, `16384`, `15s` | HTTP server hardening for both listeners; see [docs/configuration.md](docs/configuration.md#http-server-hardening) |
| `STATE_SQLITE_PATH` | No | `/var/lib/tempogate/state.db` | SQLite state-store path (back this with a PVC) |
| `STATE_SQLITE_MAX_CONNS` | No | `1` | SQLite connection pool size; do not raise (one writer) |
| `STATE_SQLITE_BUSY_TIMEOUT` | No | `5s` | How long a query waits on a locked database |
| `STATE_REAPER_INTERVAL` | No | `5m` | How often `serve` deletes expired state; `0` disables |
| `KEYS_ENCRYPTION_KEY` / `KEYS_ENCRYPTION_KEY_FILE` | No | _(empty)_ | Base64 32-byte key (or a file holding it) that encrypts the stored signing key. See [Signing-key encryption](docs/configuration.md#signing-key-encryption) |
| `KEYS_RETIREMENT_GRACE` | No | `4h` | How long a retired signing key stays in JWKS and keeps verifying |
| `KEYS_RELOAD_INTERVAL` | No | `30s` | How often `serve` re-reads signing keys from the state store |
| `KEYS_PUBLISH_DELAY` | No | `5m` | How long a new signing key is published before it signs; must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`. See the [rotation runbook](docs/configuration.md#rotation-runbook) |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_REQUESTS` | No | `true` | One access-log line per HTTP request (no query strings, headers or bodies) |
| `TEMPOGATE_ISSUER` | No | _(empty)_ | **Client-side**, read by `tempogate login` (not the server). Equivalent to `--issuer` |
| `TEMPOGATE_LOGIN_MODE` | No | _(empty)_ | **Client-side**. `device` makes `tempogate login` use the device flow, as `--device` does; an explicit `--device` or `--device=false` wins |

[docs/configuration.md](docs/configuration.md) describes every setting in detail.

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
make tools         # install pinned gci + golangci-lint + govulncheck + actionlint into ./.bin
make check         # fmt + vet + gci + Go version sync; fails on a dirty tree
make lint          # golangci-lint
make vuln          # govulncheck; fails on reachable vulnerabilities
make check-supply-chain  # actionlint + digest pins + CI runs exactly `make ci`
make test          # check + race + coverage
make ci            # what GitHub Actions runs
make test-e2e      # container-backed acceptance proofs (needs Docker)
```

`make test-e2e` stands up `temporalio/ui`, a JWKS-backed `temporal-frontend`, a mock Google IdP, and headless Chrome via testcontainers.
It proves the login flows end to end (Web UI SSO, and the `tempogate login` CLI loopback and device flows), plus integration keys, the refresh-token lifecycle, multi-tenant scoping and the hardening checks.
The login tests assert that the minted JWT authenticates a gRPC `ListNamespaces` and that an unauthenticated call is rejected.
It is behind a `//go:build e2e` tag and a dedicated CI job, so the default `make ci` stays fast.

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
- [examples/docker-compose/](examples/docker-compose/README.md) - the full
  stack locally, one command (dev only: its mock IdP signs anyone in)
- [examples/kind/](examples/kind/README.md) — deploy to a local Kubernetes
  cluster via the chart
- [examples/google-oauth-setup.md](examples/google-oauth-setup.md) —
  create the upstream Google OAuth client
- [charts/tempogate/README.md](charts/tempogate/README.md) — Helm deployment

## Security

The state database is created owner-only (`0600`, in a `0700` directory when tempogate creates it).
Bearer secrets in it (refresh tokens, authorization and device codes, session ids) are stored only as SHA-256 hashes.
The signing key is stored as plain PEM unless you set `KEYS_ENCRYPTION_KEY`; set it in production so a leaked backup or volume snapshot cannot mint tokens.
See [docs/configuration.md](docs/configuration.md#state-store-sqlite).

Report vulnerabilities via
[GitHub Security Advisories](https://github.com/onhotpath/tempogate/security/advisories/new)
— see [SECURITY.md](SECURITY.md). **Do not** open public issues for security
reports.

## License

Apache 2.0 — see [LICENSE](LICENSE).
