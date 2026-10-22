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
| `HTTP_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDRs or addresses of reverse proxies in front of tempogate. Only for a connection from one of these is the client address taken from `X-Forwarded-For`. See [Abuse controls](#abuse-controls). |
| `HTTP_RATE_LIMIT_AUTHORIZE` | `30` | Requests per minute per client address to `GET /authorize`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION` | `10` | Requests per minute per client address to `POST /device_authorization`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_VERIFICATION` | `20` | Requests per minute per client address to `POST /device` (the user_code form). `0` disables. |
| `HTTP_RATE_LIMIT_TOKEN` | `60` | Requests per minute per client address to `POST /token`. `0` disables. |

### Abuse controls

The public endpoints accept anonymous requests, and `/authorize` and `/device_authorization` write a row per request, so tempogate bounds both the size and the rate of what an unauthenticated caller can send.

**Parameter caps.**
Oversized parameters are refused with `400 invalid_request` before anything is stored:
`state` and `nonce` at most 512 bytes, `scope` at most 1 KiB, `client_id` at most 256 bytes, `redirect_uri` at most 2 KiB, and `code_challenge` exactly 43 base64url characters (an S256 challenge).
At `/token`, `code`, `refresh_token`, `device_code` and `code_verifier` are capped at 1 KiB, a generous ceiling over the 43-character values tempogate issues.

**Rate limits.**
Each `HTTP_RATE_LIMIT_*` endpoint allows a burst of that many requests per client address, refilling evenly over a minute.
IPv6 clients are counted per /64.
A request over the budget gets `429 Too Many Requests` with `Retry-After` (seconds until one more request is allowed) and, on the OAuth endpoints, an RFC 6749 error body `{"error": "temporarily_unavailable", ...}`.
The budgets live in process memory: they reset on restart, and each replica would count separately.
A fronting proxy or WAF may rate-limit instead; set the matching limit to `0` to leave it to the proxy.
The Temporal Web UI calls `/token` from its server for every user's sign-in and refresh, so all UI users share the UI server's `/token` budget: raise `HTTP_RATE_LIMIT_TOKEN` if many users sign in at once.

**Client address behind a proxy.**
By default the client address is the TCP peer.
Behind an ingress or load balancer every request then comes from the proxy, so all clients share one budget and one noisy client can lock everyone out.
Set `HTTP_TRUSTED_PROXIES` to the proxies' addresses (for a Kubernetes ingress controller, typically the pod CIDR) to fix this.
For a connection from a trusted proxy, tempogate walks `X-Forwarded-For` from the right and uses the first address that is not itself a trusted proxy: entries further left were written by the client and are ignored.
A connection from any other address is its own client, whatever `X-Forwarded-For` it sends.
Never list a range that clients can connect from directly, or they can choose their own budget.

### API documentation

| Variable | Default | Notes |
| --- | --- | --- |
| `API_DOCS_ENABLED` | `false` | Serves the OpenAPI document (`/openapi.json`, `/openapi.yaml`), the docs page (`/docs`) and the JSON schemas (`/schemas/*`) on both listeners, under the OIDC base path on the public one. Off, they return `404` and response bodies carry no `$schema` link. `tempogate gen-oas` emits the specs either way. |

### State store (SQLite)

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_SQLITE_PATH` | `/var/lib/tempogate/state.db` | Holds the signing keypair, auth codes, and refresh tokens (including consumed ones, kept to detect reuse). Back it with durable storage: losing it rotates signing keys and invalidates every issued refresh token. See below for how its contents are protected. |
| `STATE_SQLITE_MAX_CONNS` | `1` | SQLite tolerates one writer. Do not raise; horizontal scaling needs a shared backend (not yet available). |
| `STATE_SQLITE_BUSY_TIMEOUT` | `5s` | Go duration; how long a query waits on a locked database before erroring. |
| `STATE_REAPER_INTERVAL` | `5m` | Go duration; how often `serve` deletes expired state (see below). `0` disables the reaper. |

The database file and its `-wal` / `-shm` companions are created (and on every start, reset to) mode `0600`, whatever the umask.
A missing state directory is created `0700`.
An existing directory, such as a mounted volume, is left as it is; tempogate logs a warning if other users can enter it (group access, as a Kubernetes `fsGroup` grants, is expected and not reported).

Refresh tokens (including consumed ones), authorization codes, device codes and verification-page session ids are stored only as their SHA-256, so a copy of the database (a backup, a volume snapshot) holds nothing a client could present.
The device flow's `user_code` is the exception: it is short enough that its hash would be reversed by trying every code, and approving it needs a signed-in browser session anyway.
Upgrading to migration `0012` deletes the existing rows of those tables, because SQLite cannot compute the hashes: every user signs in once more after the upgrade.

`serve` deletes expired rows every `STATE_REAPER_INTERVAL`, starting at boot: pending authorization requests, authorization codes, device codes and verification-page sessions once they expire, and denylisted integration-key ids an hour after the key's `expires_at` (keys without one stay denylisted).
Refresh tokens go a whole session (family) at a time, and only once every token in it is dead: the session is past `OIDC_REFRESH_MAX_LIFETIME`, or every token has expired and was rotated or revoked.
Until then rotated tokens are kept, so presenting one is still detected as reuse.
Rows are deleted in batches so a large sweep does not hold up sign-ins; counts are logged at `debug`, failures at `warn`.

### Signing-key encryption

| Variable | Default | Notes |
| --- | --- | --- |
| `KEYS_ENCRYPTION_KEY` | _(empty)_ | Base64-encoded 32-byte key-encryption key (KEK). When set, the private signing key is stored AES-256-GCM encrypted under it instead of as plain PEM. Generate once with `openssl rand -base64 32` and supply via a Secret. |
| `KEYS_ENCRYPTION_KEY_FILE` | _(empty)_ | Path to a file holding the same base64 value (surrounding whitespace ignored), e.g. a mounted Kubernetes Secret. Set at most one of the two. |

Without a KEK the signing key is readable by anyone who can read the database, and with it they can mint tokens Temporal accepts.
With a KEK, the database alone is not enough: keep the KEK somewhere a database backup does not go.

- New keys (the first boot, `tempogate keys generate`) are written encrypted.
- Keys stored before the KEK was set keep working, and `tempogate serve` warns about them. Encrypt them once with `tempogate keys encrypt` (safe to repeat; run it in the serving pod in Kubernetes, e.g. `kubectl exec deploy/tempogate -- /tempogate keys encrypt`).
- Once a key is encrypted, `tempogate serve` refuses to start without the KEK, or with a different one, and says so.
- Encrypted rows are bound to their key id, so they cannot be swapped between rows.
- There is no KEK rotation yet. Losing the KEK loses the signing keys: remove the `keypairs` rows and restart to mint a new key, after which every token issued before stops validating.
- Rolling back to a release without KEK support fails at startup once a key is encrypted.

### OIDC — server identity and Google federation

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | for real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer`, derives `jwks_uri`. May include a path for [sub-path hosting](#sub-path-hosting). |
| `OIDC_CLIENTS` | for any login | _(empty)_ | Comma-separated `id:redirect_uri`. The first `:` splits id from URI, so the URI keeps its scheme. Each value is an **exact** redirect URI, never a prefix: see [Redirect URI registration](#redirect-uri-registration). Repeat an id to register several URIs. An empty value (`tempogate-device:`) registers a device-only client. **Every client here is public - PKCE is mandatory.** Register the loopback CLI as `tempogate-cli:http://127.0.0.1/callback`; the device flow additionally needs `tempogate-device:` and `tempogate-device-ui:<issuer>/device/sso-callback` (see [docs/cli-device-login.md](cli-device-login.md)); the server refuses to start if `tempogate-device-ui` is not registered for that exact callback. Invalid entries stop the server at startup. |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | no | `false` | Dev only. Allows plain-`http` redirect URIs for non-loopback hosts in `OIDC_CLIENTS` (e.g. `http://temporal-ui:8080/auth/sso/callback` in a local Docker Compose stack). Leave it off in production: a code sent over plain http to a remote host can be read on the network. |
| `OIDC_CLIENT_SECRETS` | no | _(empty)_ | Comma-separated `id:secret`. The deliberately-separate, auditable opt-in that promotes a registered client to **confidential** (the PKCE carve-out) — e.g. the Temporal Web UI, which does not implement PKCE; also `tempogate-device-ui`, which tempogate uses as a client of itself when bouncing the verification page through Google SSO. An entry for an unregistered id fails fast. See [docs/pkce-and-confidential-clients.md](pkce-and-confidential-clients.md). |
| `OIDC_ALLOWED_DOMAINS` | for any login | _(empty)_ | Comma-separated, exact-match email-domain gate applied to Google's verified email after sign-in, and re-applied to the session's email on every refresh: removing a domain ends its users' sessions at their next refresh (and revokes them). **Empty means nobody is admitted.** |
| `OIDC_ACCESS_TOKEN_TTL` | no | `4h` | Go duration; lifetime of each access token. This is also the revoke lag at the Temporal frontend, which verifies tokens against the JWKS only. Must be shorter than `OIDC_REFRESH_TOKEN_TTL`. ID tokens always live 5 minutes. |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | no | `temporal` | The `aud` of every access token, integration keys included. Set Temporal's `global.authorization.audience` (Temporal v1.29.0+) to the same value so the frontend refuses tokens minted for anything else. Must not be empty. See [Access tokens and ID tokens](#access-tokens-and-id-tokens). |
| `OIDC_REFRESH_TOKEN_TTL` | no | `168h` | Go duration (7 days); idle lifetime of each rotated refresh token. A session not refreshed for this long ends. Must not exceed `OIDC_REFRESH_MAX_LIFETIME`. |
| `OIDC_REFRESH_MAX_LIFETIME` | no | `720h` | Go duration (30 days); absolute session lifetime counted from the original sign-in. Rotation never extends it: no refresh token outlives sign-in + this value, so every user goes back through Google at least this often. Not to be confused with `OIDC_SESSION_TTL`, which is the device-flow verification page's cookie. See [Refresh-token sessions](#refresh-token-sessions). |
| `OIDC_SESSION_SIGNING_KEY` | yes | _(empty)_ | Base64url-encoded 32-byte HMAC key. Signs the verification-page session cookie and the SSO-bounce `state` parameter used by the [device flow](cli-device-login.md), each under its own domain-separation label so neither verifies as the other. Generate once with `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='`, keep stable across rolling restarts, and supply via a Secret. **Tempogate refuses to boot** if this is empty, not base64url, or does not decode to exactly 32 bytes. |
| `OIDC_SESSION_TTL` | no | `5m` | Go duration; TTL of the verification-page session cookie used by the [device flow](cli-device-login.md). The cookie is path-scoped to the device-flow routes (`/device` at a root issuer, `<issuer-path>/device` under [sub-path hosting](#sub-path-hosting)) and is not a general-purpose login session; keeping it short bounds how long an approval window stays open. It is `Secure` unless `OIDC_ISSUER` is plain `http://` (local or compose setups), because browsers never send a `Secure` cookie back over http. |
| `OIDC_GOOGLE_CLIENT_ID` | for any login | _(empty)_ | Upstream Google OAuth client id. |
| `OIDC_GOOGLE_CLIENT_SECRET` | for any login | _(empty)_ | Upstream Google OAuth client secret. Supply via a Secret; never commit it. |
| `OIDC_GOOGLE_AUTH_ENDPOINT` | no | `https://accounts.google.com/o/oauth2/v2/auth` | Override only to point the flow at a mock IdP (testing/examples). |
| `OIDC_GOOGLE_TOKEN_ENDPOINT` | no | `https://oauth2.googleapis.com/token` | Where the callback exchanges the code for Google's `id_token`. Override for a mock IdP. |
| `OIDC_GOOGLE_ISSUER_URL` | no | `https://accounts.google.com` | Expected `iss` of Google's `id_token` and the OIDC-discovery/JWKS base the callback verifies its signature against. Override for a mock IdP. |

**Minimum for real SSO:** `OIDC_ISSUER`, `OIDC_CLIENTS`,
`OIDC_ALLOWED_DOMAINS`, `OIDC_SESSION_SIGNING_KEY`,
`OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET`.

**Device verification rate limits** have no configuration keys.
Failed user-code attempts on the verification pages are limited to 20 per minute per client IP and 5 per minute per verification session, in memory on each replica (see [docs/cli-device-login.md](cli-device-login.md#security-notes)).
The client IP is the TCP peer; `X-Forwarded-For` is not read, so behind a reverse proxy all clients share the proxy's IP budget (one client spending it throttles code entry for the rest for up to a minute) and the per-session budget still applies.

### Access tokens and ID tokens

`/token` returns two different JWTs, both signed with the keys published at `/.well-known/jwks.json`:

| | `access_token` | `id_token` |
| --- | --- | --- |
| For | Temporal (gRPC frontend, Web UI API calls, `tempogate token`) | the relying party's login only ([OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)) |
| JWS `typ` | `at+jwt` ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)) | `JWT` |
| `aud` | `OIDC_ACCESS_TOKEN_AUDIENCE` (`temporal`) | the requesting `client_id` |
| Claims | `sub`, `email`, `permissions`, `client_id` | `sub`, `email`, `email_verified`, `auth_time`, `nonce` (when sent at `/authorize`) |
| Lifetime | `OIDC_ACCESS_TOKEN_TTL` (`4h`) | 5 minutes |

The ID token has no `permissions` claim, and Temporal's default ClaimMapper grants roles only from `permissions`, so an ID token presented to Temporal is refused.
A relying party that receives or leaks an ID token holds nothing Temporal would authorize.
Integration keys minted on the admin API are access tokens with the same `typ` and `aud` (no `client_id`).
`/userinfo` accepts access tokens for `OIDC_ACCESS_TOKEN_AUDIENCE` only; it refuses ID tokens, tokens for another audience, and tokens minted before this split.

**Temporal Web UI.** The UI already sends the access token as its bearer and the ID token only in the `Authorization-Extras` header, which Temporal's default ClaimMapper ignores (temporalio/ui v2.32.0, `src/lib/utilities/request-from-api.ts`).
No UI setting changes.
Do not configure a custom ClaimMapper that authorizes from `Authorization-Extras`.

**Temporal audience (defense in depth).** Temporal v1.29.0 added `global.authorization.audience` ([temporalio/temporal#8067](https://github.com/temporalio/temporal/pull/8067)); when set, the frontend refuses any token whose `aud` does not contain it.
Set it to `OIDC_ACCESS_TOKEN_AUDIENCE` in the server config (it is not templated from an environment variable):

```yaml
global:
  authorization:
    jwtKeyProvider:
      keySourceURIs:
        - https://tempogate.example.com/.well-known/jwks.json
    authorizer: default
    claimMapper: default
    audience: temporal   # = OIDC_ACCESS_TOKEN_AUDIENCE
```

Temporal v1.28 and earlier (including the `1.25.2` the examples and e2e tests run) have no audience setting and ignore `aud`; they keep working unchanged with any value.
Once the audience is enforced, integration keys minted before this release (no `aud`) stop working and must be minted again.

### Refresh-token sessions

Each sign-in starts a session: a family of single-use refresh tokens that rotate on every exchange.
A refresh is refused with `invalid_grant` when the session is idle past `OIDC_REFRESH_TOKEN_TTL`, older than `OIDC_REFRESH_MAX_LIFETIME`, revoked, or its email domain is no longer in `OIDC_ALLOWED_DOMAINS`.
Presenting a token that was already rotated revokes the whole family ([RFC 9700 §4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)) and logs a `refresh_token_reuse` warning with `family_id`, `client_id` and `email`; a domain refusal logs `refresh_domain_not_allowed`.
Token values are never logged.

Operators manage sessions with the server binary, against the same state store (`STATE_SQLITE_PATH`):

```bash
tempogate sessions list [--email alice@example.com]   # family id, client, email, sign-in, last rotation, expiry
tempogate sessions revoke --email alice@example.com   # every session of a user
tempogate sessions revoke --family <family-id>        # one session
```

In Kubernetes, run them in the serving pod, e.g. `kubectl exec deploy/tempogate -- /tempogate sessions revoke --email alice@example.com`.
Revocation stops refreshes immediately; access tokens already issued remain valid until they expire (`OIDC_ACCESS_TOKEN_TTL`).
The integration-key jti denylist is not consulted for refresh tokens.

Redeeming an authorization code twice is refused, and the session the first redemption started is revoked ([RFC 6749 §4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2)), logged as `auth_code_reuse`.
Redeemed codes are kept (hashed) until they expire so a replay is recognised; the access token already issued stays valid at Temporal until it expires.

Upgrading to migration `0011` keeps existing sessions: each existing refresh token becomes its own family, with its sign-in time set to when it was last refreshed, so it ends at most `OIDC_REFRESH_MAX_LIFETIME` later.

### Redirect URI registration

`/authorize` only sends a code to a `redirect_uri` that matches a registered value, following [RFC 9700 §2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1) and [RFC 8252 §7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3).

| Entry | Kind | Matches |
| --- | --- | --- |
| `temporal-ui:https://temporal.example.com/auth/sso/callback` | exact | Only that exact string. No case, percent-encoding, trailing-slash or `..` variations. |
| `tempogate-cli:http://127.0.0.1/callback` | loopback | `http://127.0.0.1:<any port>/callback`, with no query. Also `http://[::1]/<path>`. `localhost` is **not** loopback: it gets exact matching. |
| `tempogate-device:` | device-only | Nothing at `/authorize`. The client may only use the device authorization grant (and refresh). |

Every registered URI must be absolute, with a host and a path, and no userinfo or fragment.
Loopback entries must omit the port, because any port is accepted.
Non-loopback entries must use `https` unless `OIDC_ALLOW_INSECURE_REDIRECT_URIS=true`.
A client with redirect URIs cannot use `/device_authorization`, and a device-only entry cannot be combined with redirect URI entries for the same id.
Prefix-shaped values from older releases (`tempogate-cli:http://127.0.0.1:`, `ui:https://ui.example.com`) are rejected at startup with an error naming the entry.

Errors at `/authorize` before the client and `redirect_uri` are validated (unknown client, unregistered URI, oversized parameters) are shown to the browser as JSON.
After that, errors (an unsupported `response_type`, a missing `openid` scope, missing or malformed PKCE) are sent back to the client's `redirect_uri` as `error` and `error_description`, with the client's `state` ([RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)).
Every authorization response, success or error, carries `iss` ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)), as discovery advertises with `authorization_response_iss_parameter_supported`.

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
- **The device-flow session cookie follows the prefix:** it is scoped to
  `/idp/device`, so the proxy must preserve the path as-is.

A root issuer (no path) behaves exactly as a path-less deployment always has.

## Security headers

Every response from both listeners carries:

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |

A few pages replace the defaults with their own, and all of them keep `frame-ancestors 'none'`:

- The device verification pages send their own CSP, which allows their inline stylesheet by hash and, on the code entry page, adds the upstream IdP's origin to `form-action`. They also send `Referrer-Policy: same-origin`, because under `no-referrer` the browser sends `Origin: null` on the Approve/Deny POST and the origin check rejects it.
- With `API_DOCS_ENABLED=true`, `/docs` sends Huma's own CSP, which allows the renderer script and stylesheet it loads from `unpkg.com`.

tempogate does not send `Strict-Transport-Security`.
TLS terminates at your proxy or ingress, which knows whether the hostname is HTTPS-only, so set HSTS there.
Keep the headers above intact at the proxy: the anti-framing protection for the device approval page depends on them.

The public `/healthz` answers `{"status":"ok"}` only.
The build version is on the admin listener's `/admin/healthz` and from `tempogate version`.

## See also

- [Helm chart values](../charts/tempogate/README.md#values) — the same
  settings as chart `values.yaml` keys, plus Secret wiring.
- [docs/getting-started.md](getting-started.md) — these settings in a working
  end-to-end context.
