# Configuration reference

Every tempogate setting, its default, and when you need it.

## How configuration is resolved

Three layers, last wins:

1. **Built-in defaults** (the table below).
2. **An optional `application.yaml`** — searched in the working directory and
   up to three parent directories, or an explicit path passed to the binary.
   Nested keys are normal YAML (`oidc: { issuer: ... }`).
3. **Environment variables** — these **override** the file.

Environment is the recommended surface for containers and Kubernetes. Nested
config keys flatten with a **`_`** separator: `oidc.google.client_id`
becomes `OIDC_GOOGLE_CLIENT_ID`.

## Environment variables

### Logging

| Variable | Default | Notes |
| --- | --- | --- |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |

### HTTP listener

| Variable | Default | Notes |
| --- | --- | --- |
| `HTTP_LISTENER` | `127.0.0.1:8000` | `host:port` for the single public listener (OIDC/OAuth2 + `/healthz` + `/readyz`). The loopback default is unreachable through a container/Service — set `0.0.0.0:8000` in-cluster. |

### State store (SQLite)

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_SQLITE_PATH` | `/var/lib/tempogate/state.db` | Holds the signing keypair, auth codes, and refresh tokens. Back it with durable storage — losing it rotates signing keys and invalidates every issued refresh token. |
| `STATE_SQLITE_MAX_CONNS` | `1` | SQLite tolerates one writer. Do not raise; horizontal scaling needs a shared backend (not yet available). |
| `STATE_SQLITE_BUSY_TIMEOUT` | `5s` | Go duration; how long a query waits on a locked database before erroring. |

### OIDC — server identity and Google federation

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | for real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer`, derives `jwks_uri`. May include a path for [sub-path hosting](#sub-path-hosting). |
| `OIDC_CLIENTS` | for any login | _(empty)_ | Comma-separated `id:redirect_uri_prefix`. The first `:` splits id from prefix, so the prefix may contain a scheme. **Every client here is public — PKCE is mandatory.** Register the loopback CLI as `tempogate-cli:http://127.0.0.1:`; the device flow additionally needs `tempogate-device:` (no redirect URI — the CLI does not use one) and `tempogate-device-ui:<issuer>/device/sso-callback` (see [docs/cli-device-login.md](cli-device-login.md)). |
| `OIDC_CLIENT_SECRETS` | no | _(empty)_ | Comma-separated `id:secret`. The deliberately-separate, auditable opt-in that promotes a registered client to **confidential** (the PKCE carve-out) — e.g. the Temporal Web UI, which does not implement PKCE; also `tempogate-device-ui`, which tempogate uses as a client of itself when bouncing the verification page through Google SSO. An entry for an unregistered id fails fast. See [docs/pkce-and-confidential-clients.md](pkce-and-confidential-clients.md). |
| `OIDC_ALLOWED_DOMAINS` | for any login | _(empty)_ | Comma-separated, exact-match email-domain gate applied to Google's verified email after sign-in. **Empty means nobody is admitted.** |
| `OIDC_SESSION_SIGNING_KEY` | yes | _(empty)_ | Base64url-encoded 32-byte HMAC key. Signs the verification-page session cookie and the SSO-bounce `state` parameter used by the [device flow](cli-device-login.md). Generate once with `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='`, keep stable across rolling restarts, and supply via a Secret. **Tempogate refuses to boot** if this is empty, not base64url, or does not decode to exactly 32 bytes. |
| `OIDC_SESSION_TTL` | no | `5m` | Go duration; TTL of the verification-page session cookie used by the [device flow](cli-device-login.md). The cookie is path-scoped to the device-flow routes (e.g. `/device*` at a root issuer, `<issuer-path>/device*` under [sub-path hosting](#sub-path-hosting)) and is not a general-purpose login session — keeping it short bounds how long an approval window stays open. |
| `OIDC_GOOGLE_CLIENT_ID` | for any login | _(empty)_ | Upstream Google OAuth client id. |
| `OIDC_GOOGLE_CLIENT_SECRET` | for any login | _(empty)_ | Upstream Google OAuth client secret. Supply via a Secret; never commit it. |
| `OIDC_GOOGLE_AUTH_ENDPOINT` | no | `https://accounts.google.com/o/oauth2/v2/auth` | Override only to point the flow at a mock IdP (testing/examples). |
| `OIDC_GOOGLE_TOKEN_ENDPOINT` | no | `https://oauth2.googleapis.com/token` | Where the callback exchanges the code for Google's `id_token`. Override for a mock IdP. |
| `OIDC_GOOGLE_ISSUER_URL` | no | `https://accounts.google.com` | Expected `iss` of Google's `id_token` and the OIDC-discovery/JWKS base the callback verifies its signature against. Override for a mock IdP. |

**Minimum for real SSO:** `OIDC_ISSUER`, `OIDC_CLIENTS`,
`OIDC_ALLOWED_DOMAINS`, `OIDC_SESSION_SIGNING_KEY`,
`OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET`.

### Client-side (the `tempogate` CLI, not the server)

| Variable | Default | Notes |
| --- | --- | --- |
| `TEMPOGATE_ISSUER` | _(empty)_ | Read by `tempogate login` / `tempogate token` to find the server. Equivalent to the `--issuer` flag. Never read by `tempogate serve`. |

## Sub-path hosting

`OIDC_ISSUER` may contain a path, so tempogate can share a hostname with
another app:

```
OIDC_ISSUER=https://tempogate.example.com/idp
```

The **entire OIDC surface** then serves under that prefix
(`/idp/.well-known/openid-configuration`, `/idp/authorize`, `/idp/token`,
`/idp/userinfo`, `/idp/callback/google`, …), and the discovery document
advertises issuer-relative endpoints, so the `iss` claim, the advertised
endpoints, and the served routes stay in lockstep. Route the prefix to
tempogate at your proxy and **strip nothing** — tempogate owns the prefix
natively.

Two consequences:

- **Health probes stay at the root.** `/healthz` and `/readyz` are *not*
  moved under the prefix — they are infra probes, not part of the public
  OIDC surface. Point Kubernetes liveness/readiness at `/healthz` / `/readyz`
  regardless of the issuer path.
- **The Google redirect URI must include the prefix:** register
  `https://tempogate.example.com/idp/callback/google` (issuer +
  `/callback/google`) in the Google OAuth client. See
  [examples/google-oauth-setup.md](../examples/google-oauth-setup.md).

A root issuer (no path) behaves exactly as a path-less deployment always has.

## See also

- [Helm chart values](../charts/tempogate/README.md#values) — the same
  settings as chart `values.yaml` keys, plus Secret wiring.
- [docs/getting-started.md](getting-started.md) — these settings in a working
  end-to-end context.
