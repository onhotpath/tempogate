# Configuration reference

Every tempogate setting, its default, and when you need it.

## How configuration is resolved

Three layers, last wins:

1. **Built-in defaults** (the table below).
2. **An optional yaml file.**
   Nested keys are normal YAML (`oidc: { issuer: ... }`).
   Which file:
   - `--config <path>`, accepted by every subcommand (`tempogate --config /etc/tempogate.yaml serve`), else
   - the `TEMPOGATE_CONFIG` environment variable, else
   - `application.yaml` in the working directory, if present.
     Parent directories are **not** searched, so a file planted above the working directory cannot repoint the server.

   A file named by `--config` or `TEMPOGATE_CONFIG` that cannot be read is fatal.
   An `application.yaml` in the working directory that cannot be read (for example the image's `/home/nonroot` when the container runs under a uid other than the default `65532`) is skipped with a warning.
   Run with `LOG_LEVEL=debug` to log which file was loaded.
3. **Environment variables** - these **override** the file.

Environment is the recommended surface for containers and Kubernetes. Nested
config keys flatten with a **`_`** separator: `oidc.google.client_id`
becomes `OIDC_GOOGLE_CLIENT_ID`.

## Environment variables

### Logging

| Variable | Default | Notes |
| --- | --- | --- |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `LOG_REQUESTS` | `true` | One structured access-log line per HTTP request on both listeners; see [Request logs](#request-logs). `false` turns it off, e.g. when an ingress or mesh already logs every request. |

### HTTP listener

| Variable | Default | Notes |
| --- | --- | --- |
| `HTTP_LISTENER` | `127.0.0.1:8000` | `host:port` for the single public listener (OIDC/OAuth2 + `/healthz` + `/readyz`). The loopback default is unreachable through a container/Service — set `0.0.0.0:8000` in-cluster. |
| `HTTP_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDRs or addresses of reverse proxies in front of tempogate. Only for a connection from one of these is the client address taken from `X-Forwarded-For`. See [Abuse controls](#abuse-controls). |
| `HTTP_RATE_LIMIT_AUTHORIZE` | `30` | Requests per minute per client address to `GET /authorize`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION` | `10` | Requests per minute per client address to `POST /device_authorization`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_VERIFICATION` | `20` | Requests per minute per client address to `POST /device` (the user_code form). `0` disables. |
| `HTTP_RATE_LIMIT_TOKEN` | `60` | Requests per minute per client address to `POST /token`. `0` disables. |

### HTTP server hardening

Applied identically to the public and the admin listener.
Durations are Go durations; `0` disables that timeout (not recommended).

| Variable | Default | Notes |
| --- | --- | --- |
| `SERVER_READ_HEADER_TIMEOUT` | `10s` | Time allowed to read the request headers. Bounds slow-header (slowloris) clients. |
| `SERVER_READ_TIMEOUT` | `15s` | Time allowed to read the whole request, headers and body. Bounds slow-body clients; request bodies are small form posts, capped at 1 MiB. |
| `SERVER_WRITE_TIMEOUT` | `30s` | Time from the end of the request headers until the response is written. Covers the handler itself, so it must outlast the slowest legitimate request: the Google callback's code exchange and JWKS fetch. No endpoint streams or long-polls (device-flow polling returns immediately). |
| `SERVER_IDLE_TIMEOUT` | `60s` | How long an idle keep-alive connection stays open between requests. |
| `SERVER_MAX_HEADER_BYTES` | `16384` | Upper bound on the request header block (net/http adds 4 KiB of slack). Larger requests get `431 Request Header Fields Too Large`. `0` falls back to the net/http default of 1 MiB. |
| `SERVER_SHUTDOWN_TIMEOUT` | `15s` | Grace in-flight requests get after `SIGTERM`; connections still active afterwards are force-closed (logged as `graceful shutdown: context deadline exceeded`); `0` force-closes immediately. Keep it below the pod's `terminationGracePeriodSeconds` (Kubernetes default `30s`) and under the process's 1-minute stop ceiling. |

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
| `API_DOCS_ENABLED` | `false` | Dev only. Serves the OpenAPI document (`/openapi.json`, `/openapi.yaml`), the docs page (`/docs`) and the JSON schemas (`/schemas/*`) on the public listener, under the OIDC base path. `serve` refuses to start with it on unless `OIDC_ISSUER` is plain `http://`, so it cannot be enabled in an https deployment. The admin listener never serves them, whatever this says. Off, they return `404` and response bodies carry no `$schema` link. Anywhere else, use `tempogate gen-oas` (public spec) and `tempogate gen-oas --admin` (admin spec), which work either way. |

### Admin API

The admin API (`/admin/keys` for integration keys, `/admin/signing-keys` for [signing-key retirement](#revocation-and-signing-key-retirement), `/admin/sessions` for [refresh-token sessions](#refresh-token-sessions), plus the `/admin/healthz` liveness probe) is served on its own listener, never on the public one.
Every `/admin/*` route except `/admin/healthz` requires `Authorization: Bearer <admin token>`.
The same listener serves Prometheus [`GET /metrics`](#metrics), outside `/admin/*` and without the token.
Only the token's SHA-256 digest is configured, so the token itself never sits in env, yaml, or a ConfigMap.

| Variable | Default | Notes |
| --- | --- | --- |
| `ADMIN_LISTENER` | `127.0.0.1:8081` | `host:port` for the admin listener. Keep it on loopback unless you must manage keys from another host; a non-loopback bind also needs `ADMIN_ALLOWED_HOSTS`. |
| `ADMIN_TOKEN_SHA256` | _(empty)_ | Comma-separated lowercase-hex SHA-256 digests of the accepted admin tokens. List two during a rotation, then drop the old one. **Empty locks the admin API:** every route but `/admin/healthz` answers 401 and tempogate logs a startup warning. A malformed entry makes `serve` refuse to boot. |
| `ADMIN_ALLOWED_HOSTS` | `127.0.0.1:<port>,localhost:<port>,[::1]:<port>` | Comma-separated `host[:port]` values accepted in the `Host` header; an entry without a port matches any port. Other hosts get **421 Misdirected Request** before the token is checked, which defeats DNS rebinding from a browser. The default takes `<port>` from `ADMIN_LISTENER` and names only loopback, even for a `0.0.0.0` bind: **set it to the names your callers use** (e.g. `tempogate-admin.tempogate.svc:8081`). |
| `ADMIN_ALLOW_SYSTEM_GRANTS` | `false` | Allow minting keys for the `temporal-system` namespace. Temporal treats a `temporal-system` role as cluster-wide, so these grants answer 403 unless this is `true`. Enable it only while you mint the keys that need it. |
| `ADMIN_KEYS_MAX_TTL` | `2160h` (90 days) | Go duration; the furthest in the future an integration key's `expires_at` may lie. `expires_at` is required, and a value in the past or beyond this cap answers 400. Temporal ignores revocation, so this cap bounds how long a leaked key keeps working there unless you [retire its signing key](#revocation-and-signing-key-retirement). Must be positive. |

Generate a token and its digest:

```bash
token=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
printf %s "$token" | sha256sum | cut -d' ' -f1   # -> ADMIN_TOKEN_SHA256
```

Keep `$token` in your secret manager, then call the API with it:

```bash
curl -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"namespace":"payments","role":"write","owner":"svc-payments","expires_at":"2026-12-31T00:00:00Z"}' \
  http://127.0.0.1:8081/admin/keys
```

Every mint and revoke is logged as one `admin audit` line (`action`, `outcome`, `id`, `jti`, `namespace`, `role`, `owner`, `caller`, `remote_addr`).
Every signing-key retirement is logged the same way with `action=retire_signing_key`, the `kid` and `force`.
Every session revoke is logged with `action=revoke_sessions`, the selector (`email`, `subject` or `family_id`) and `revoked`, the number of live sessions it ended.
Rejected requests are logged as `admin request rejected` at warn level with a `reason`.
`caller` is the first 8 hex characters of the matched digest, so you can tell rotated tokens apart without logging them.

### Signing keys

| Variable | Default | Notes |
| --- | --- | --- |
| `KEYS_RETIREMENT_GRACE` | `4h` | Go duration; how long a retired signing key stays in `/.well-known/jwks.json` and keeps verifying. After it, every token signed by that key stops verifying, at tempogate and (once it refreshes its JWKS) at Temporal, whatever its `exp`. The default matches the 4 h access-token TTL, so tokens minted just before a retirement live out their natural life. `0` unpublishes a key the moment it is retired. Must not be negative. |
| `KEYS_RELOAD_INTERVAL` | `30s` | Go duration; how often `serve` re-reads signing keys from the state store, so `tempogate keys generate --force` and `tempogate keys retire` run from another process take effect without a restart. A retire through the admin API applies immediately. Must be positive. |
| `KEYS_PUBLISH_DELAY` | `5m` | Go duration; how long a new signing key is published in `/.well-known/jwks.json` before it signs. Until then the previous non-retired key keeps signing; when there is no other non-retired key (fresh install, or every key retired) the new key signs at once. **Must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`** (see [below](#why-new-keys-wait-before-signing)). `0` signs with a new key as soon as `serve` loads it. Must not be negative. |

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
  `tempogate keys generate`, `keys list` and `keys retire` read the stored keys too, so they need the same KEK, and a running server keeps its loaded keys if a reload cannot open them.
- Encrypted rows are bound to their key id, so they cannot be swapped between rows.
- There is no KEK rotation yet. Losing the KEK loses the signing keys: remove the `keypairs` rows and restart to mint a new key, after which every token issued before stops validating.
- Rolling back to a release without KEK support fails at startup once a key is encrypted.

### OIDC — server identity and Google federation

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | for real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer`, derives `jwks_uri`. May include a path for [sub-path hosting](#sub-path-hosting). **Must be `https://`** unless the host is loopback (`localhost`, `127.0.0.0/8`, `::1`): `tempogate serve` refuses to start otherwise. |
| `OIDC_ALLOW_INSECURE_ISSUER` | no | `false` | **Development only.** Lets `serve` start with a plain-http `OIDC_ISSUER` on a non-loopback host (e.g. the docker-compose demo's `http://tempogate:8000`), logging a warning. Relying parties fetch the discovery document and signing keys from the issuer, so over plain http anyone on the path can substitute keys. `migrate`, `keys` and `version` never check the issuer. |
| `OIDC_CLIENTS` | for any login | _(empty)_ | Comma-separated `id:redirect_uri`. The first `:` splits id from URI, so the URI keeps its scheme. Each value is an **exact** redirect URI, never a prefix: see [Redirect URI registration](#redirect-uri-registration). Repeat an id to register several URIs. An empty value (`tempogate-device:`) registers a device-only client. **Every client here is public - PKCE is mandatory.** Register the loopback CLI as `tempogate-cli:http://127.0.0.1/callback`; the device flow additionally needs `tempogate-device:` and `tempogate-device-ui:<issuer>/device/sso-callback` (see [docs/cli-device-login.md](cli-device-login.md)); the server refuses to start if `tempogate-device-ui` is not registered for that exact callback. Invalid entries stop the server at startup. |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | no | `false` | Dev only. Allows plain-`http` redirect URIs for non-loopback hosts in `OIDC_CLIENTS` (e.g. `http://temporal-ui:8080/auth/sso/callback` in a local Docker Compose stack). Leave it off in production: a code sent over plain http to a remote host can be read on the network. |
| `OIDC_CLIENT_SECRETS` | no | _(empty)_ | Comma-separated `id:secret`. The deliberately-separate, auditable opt-in that promotes a registered client to **confidential** (the PKCE carve-out) — e.g. the Temporal Web UI, which does not implement PKCE; also `tempogate-device-ui`, which tempogate uses as a client of itself when bouncing the verification page through Google SSO. An entry for an unregistered id fails fast. See [docs/pkce-and-confidential-clients.md](pkce-and-confidential-clients.md). |
| `OIDC_ALLOWED_DOMAINS` | for any login | _(empty)_ | Comma-separated, exact-match email-domain gate applied to Google's verified email after sign-in, and re-applied to the session's email on every refresh: removing a domain ends its users' sessions at their next refresh (and revokes them). **Empty means nobody is admitted.** |
| `OIDC_ALLOWED_HOSTED_DOMAINS` | recommended | _(empty)_ | Comma-separated Google Workspace domains ("Workspace mode"). When set, Google's `id_token` must carry an `hd` (hosted domain) claim in this list, on top of `email_verified` and `OIDC_ALLOWED_DOMAINS`. Exact, case-insensitive match. Empty keeps the email-domain-only gate and logs a warning at startup. See [Hosted domain (Workspace mode)](#hosted-domain-workspace-mode). |
| `OIDC_ACCESS_TOKEN_TTL` | no | `4h` | Go duration; lifetime of each access token. This is also the revoke lag at the Temporal frontend, which verifies tokens against the JWKS only. Must be shorter than `OIDC_REFRESH_TOKEN_TTL`. ID tokens always live 5 minutes. |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | no | `temporal` | The `aud` of every access token, integration keys included. Set Temporal's `global.authorization.audience` (Temporal v1.29.0+) to the same value so the frontend refuses tokens minted for anything else. Must not be empty. See [Access tokens and ID tokens](#access-tokens-and-id-tokens). |
| `OIDC_REFRESH_TOKEN_TTL` | no | `168h` | Go duration (7 days); idle lifetime of each rotated refresh token. A session not refreshed for this long ends. Must not exceed `OIDC_REFRESH_MAX_LIFETIME`. |
| `OIDC_REFRESH_MAX_LIFETIME` | no | `720h` | Go duration (30 days); absolute session lifetime counted from the original sign-in. Rotation never extends it: no refresh token outlives sign-in + this value, so every user goes back through Google at least this often. Not to be confused with `OIDC_SESSION_TTL`, which is the device-flow verification page's cookie. See [Refresh-token sessions](#refresh-token-sessions). |
| `OIDC_SESSION_SIGNING_KEY` | yes | _(empty)_ | Base64url-encoded 32-byte HMAC key. Signs the verification-page session cookie and the SSO-bounce `state` parameter used by the [device flow](cli-device-login.md), each under its own domain-separation label so neither verifies as the other, and derives the per-login PKCE verifier, nonce and browser-binding cookie of the [Google leg](#google-leg). Rotating it fails logins that are in flight (at most the 5-minute auth request lifetime). Generate once with `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='`, keep stable across rolling restarts, and supply via a Secret. **Tempogate refuses to boot** if this is empty, not base64url, or does not decode to exactly 32 bytes. |
| `OIDC_SESSION_TTL` | no | `5m` | Go duration; TTL of the verification-page session cookie used by the [device flow](cli-device-login.md). The cookie is path-scoped to the device-flow routes (`/device` at a root issuer, `<issuer-path>/device` under [sub-path hosting](#sub-path-hosting)) and is not a general-purpose login session; keeping it short bounds how long an approval window stays open. It is `Secure` unless `OIDC_ISSUER` is plain `http://` (local or compose setups), because browsers never send a `Secure` cookie back over http. |
| `OIDC_GOOGLE_CLIENT_ID` | for any login | _(empty)_ | Upstream Google OAuth client id. |
| `OIDC_GOOGLE_CLIENT_SECRET` | for any login | _(empty)_ | Upstream Google OAuth client secret. Supply via a Secret; never commit it. |
| `OIDC_GOOGLE_AUTH_ENDPOINT` | no | `https://accounts.google.com/o/oauth2/v2/auth` | Override only to point the flow at a mock IdP (testing/examples). |
| `OIDC_GOOGLE_TOKEN_ENDPOINT` | no | `https://oauth2.googleapis.com/token` | Where the callback exchanges the code for Google's `id_token`. Override for a mock IdP. |
| `OIDC_GOOGLE_ISSUER_URL` | no | `https://accounts.google.com` | Expected `iss` of Google's `id_token` and the OIDC-discovery/JWKS base the callback verifies its signature against. Override for a mock IdP. |

**Minimum for real SSO:** `OIDC_ISSUER`, `OIDC_CLIENTS`,
`OIDC_ALLOWED_DOMAINS`, `OIDC_SESSION_SIGNING_KEY`,
`OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET`.
If your users are in Google Workspace, also set `OIDC_ALLOWED_HOSTED_DOMAINS`.

**Device verification rate limits** have no configuration keys.
Failed user-code attempts on the verification pages are limited to 20 per minute per client IP and 5 per minute per verification session, in memory on each replica (see [docs/cli-device-login.md](cli-device-login.md#security-notes)).
The client IP is the TCP peer; `X-Forwarded-For` is not read, so behind a reverse proxy all clients share the proxy's IP budget (one client spending it throttles code entry for the rest for up to a minute) and the per-session budget still applies.

### Hosted domain (Workspace mode)

`OIDC_ALLOWED_DOMAINS` only checks the domain of the email address.
That is not proof that your organization controls the Google account: anyone who can receive mail at an address can create a consumer Google account for it, and Google then reports `email_verified: true`.
Google's guidance is to restrict access to an organization with the `hd` (hosted domain) claim, which Google sets only for accounts managed by a Google Workspace or Cloud organization ([OpenID Connect docs](https://developers.google.com/identity/openid-connect/openid-connect)).

Set `OIDC_ALLOWED_HOSTED_DOMAINS` to your Workspace primary domain (or several, comma-separated) to require it:

| Google account | `OIDC_ALLOWED_HOSTED_DOMAINS` empty | `OIDC_ALLOWED_HOSTED_DOMAINS=example.com` |
| --- | --- | --- |
| Workspace user `alice@example.com` (`hd=example.com`) | admitted | admitted |
| Consumer account for `alice@example.com` (no `hd`) | admitted | **rejected (403)** |
| Account in another Workspace (`hd=other.test`) with an allowed email | admitted | **rejected (403)** |

Both lists apply: the email domain must still be in `OIDC_ALLOWED_DOMAINS`.
`hd` is the organization's primary domain, so list it even when users sign in with a secondary or alias domain.
Leave the setting empty only when your email is not on Google Workspace; tempogate then logs a warning at startup.

tempogate also sends Google the `hd` request parameter (the domain when one is configured, `*` when several), so the account chooser offers the right account.
That parameter is only a UI hint: the user can edit the request, so the `hd` claim check above is the control.

### Token subject

The `sub` of every token tempogate mints for a person is the Google account's `sub`: an opaque, stable id that Google never reuses.
The email is in the `email` claim (the ID token also carries `email_verified: true`).
Do not key users on the email: Google can re-issue an address to a different account, which would otherwise inherit the previous holder's identity.
Temporal's default claim mapper authorizes from `permissions`, not `sub`.
Integration keys are unchanged: their `sub` is still the key's owner.

### Google leg

tempogate is itself an OAuth client of Google, and protects that leg independently of what the downstream client does:

- **PKCE and nonce.** Every redirect to Google carries tempogate's own S256 `code_challenge` and `nonce`. The code exchange presents the matching `code_verifier`, and the `id_token` is rejected unless its `nonce` matches. A Google code or `id_token` minted for another login therefore cannot be injected into this one. No Google Cloud console setting is needed.
- **Browser binding.** `/authorize` sets a short-lived (5 minutes), HttpOnly, `SameSite=Lax` cookie that binds the internal `state` to the browser that started the login. `/callback/google` refuses a `state` that arrives without it (`400 invalid_request`, logged as `state_not_bound_to_browser`), so an attacker cannot finish their own Google login in a victim's browser. This covers the Web UI and CLI logins and the device-flow verification page, which signs in through the same `/authorize`.
- **Cookie shape.** With an `https` issuer the cookie is `__Host-tempogate_upstream_<id>`: `Secure`, `Path=/`, no `Domain`, so a sibling subdomain cannot plant one. Browsers refuse `__Host-` and `Secure` cookies over plain http, so with an `http://` issuer (local or compose setups) it is an unprefixed `tempogate_upstream_<id>` scoped to the callback path (e.g. `/callback/google`, or `<issuer-path>/callback/google` under [sub-path hosting](#sub-path-hosting)). `<id>` differs per login, so parallel logins in one browser do not collide.
- **Derived, not stored.** The verifier, nonce and cookie value are HMAC-SHA256 derivations of the internal `state` under `OIDC_SESSION_SIGNING_KEY`, so nothing new is persisted.
- **Discovery.** Google's discovery document is fetched on the first callback after boot and cached once it succeeds. A failure is retried on a later callback after a backoff that starts at 1s and doubles up to 30s, so a transient outage heals without a restart.
- **Logging.** A failed Google sign-in (shown to the user as `502 upstream_error`) logs one warning with `op=oidc.callback` and a `cause` of `discovery_unavailable`, `code_exchange_failed` (plus the token endpoint's `oauth_error`, e.g. `invalid_grant`), `id_token_invalid`, `nonce_mismatch` or `claims_incomplete`, plus `timeout=true` when the call got no answer in time. Codes and tokens are never logged.
- **Upstream timeout.** Each call to Google (discovery, the code exchange, and id_token verification including a JWKS fetch) is bounded at 10 seconds, with 5 seconds of that for connecting and the TLS handshake. A Google that stalls fails the sign-in with the same `502 upstream_error` instead of holding the callback open. A discovery timeout is retried after the usual backoff, never cached. The bound is fixed, not configurable.

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
tempogate sessions list [--email alice@example.com] [--subject <sub>]   # family id, client, email, Google subject, sign-in, last rotation, expiry
tempogate sessions revoke --email alice@example.com   # every session of a user
tempogate sessions revoke --subject <google-sub>      # every session of a Google account, whatever its email
tempogate sessions revoke --family <family-id>        # one session; fails if no such session exists
```

In Kubernetes, run them in the serving pod, e.g. `kubectl exec deploy/tempogate -- /tempogate sessions revoke --email alice@example.com`.

The [admin API](#admin-api) offers the same operations over HTTP, so you need not exec into the pod:

```bash
curl -H "Authorization: Bearer $token" 'http://127.0.0.1:8081/admin/sessions?email=alice@example.com'   # also ?subject=
curl -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com"}' http://127.0.0.1:8081/admin/sessions/revoke   # or {"subject":...} or {"family_id":...}
```

`GET /admin/sessions` returns `{"items": [...]}` with `family_id`, `client_id`, `email`, `subject`, `auth_time`, `last_rotation_at` and `expires_at`; it never returns a token or its hash.
`POST /admin/sessions/revoke` takes exactly one of `email`, `subject` or `family_id` (anything else is 400) and answers `{"revoked": <n>}`, the number of live sessions it ended.
Revoking is idempotent: a selector that matches nothing live answers 0, except a `family_id` that never existed, which answers 404 like an unknown integration key.

Revocation stops refreshes immediately; access tokens already issued remain valid, at tempogate's `/userinfo` and at Temporal, until they expire (`OIDC_ACCESS_TOKEN_TTL`).
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
| `TEMPOGATE_ISSUER` | _(empty)_ | Read by `tempogate login` / `tempogate token` to find the server. Equivalent to the `--issuer` flag. Must be `https`, or plain `http` on a loopback host, unless `--insecure` is passed. Never read by `tempogate serve`. |
| `TEMPOGATE_LOGIN_MODE` | _(empty)_ | Set to `device` to make `tempogate login` use the [device flow](cli-device-login.md), as `--device` does. An explicit `--device` or `--device=false` flag wins. Any other value is ignored. |

## Revocation and signing-key retirement

Temporal's frontend verifies a tempogate JWT against `/.well-known/jwks.json` and its `exp`, and nothing else.
That sets what each lever can do:

| Lever | Effect at tempogate (`/userinfo`, refresh) | Effect at Temporal gRPC |
| --- | --- | --- |
| `DELETE /admin/keys/{id}` (jti denylist) | Rejected within 30 s (immediately on the instance that served the DELETE). | **None.** The token works until its `exp`. |
| `exp` (`expires_at`, capped by `ADMIN_KEYS_MAX_TTL`) | Rejected after `exp`. | Rejected after `exp`. |
| Retiring the signing key | Rejected once `KEYS_RETIREMENT_GRACE` has passed. | Rejected once the kid has left JWKS and Temporal has refreshed its JWKS cache. |

Retiring a signing key is the hard kill switch: it invalidates **every** token that key signed (human tokens, CLI tokens, integration keys), not one key.
Use it when a key leaked and its `exp` is too far away, or for routine rotation.
The `kid` of a token is in its JWT header.

### Why new keys wait before signing

Temporal's JWT key provider looks a token's `kid` up only in the JWKS it fetched on its last refresh, and it does not refetch on an unknown `kid` ([`common/authorization/default_token_key_provider.go`](https://github.com/temporalio/temporal/blob/v1.25.2/common/authorization/default_token_key_provider.go): `RsaKey` returns "RSA key not found" from the cached map; only the `refreshInterval` ticker calls `updateKeys`).
If tempogate signed with a new key the moment it saw it, every token minted before Temporal's next refresh would be rejected by temporal-frontend: login appears to succeed, Temporal calls fail.

So a new key is published in JWKS at once but signs only from `created_at + KEYS_PUBLISH_DELAY`.
Set `KEYS_PUBLISH_DELAY` above the longest time Temporal can take to see a new key:

- Temporal's `global.authorization.jwtKeyProvider.refreshInterval` (`TEMPORAL_JWT_KEY_REFRESH` in Temporal's Docker config template, default `1m`; `server.config.authorization.jwtKeyProvider.refreshInterval` in the Temporal Helm chart, see [`examples/kind/temporal-values.yaml`](../examples/kind/temporal-values.yaml)).
  With `refreshInterval` unset or `0`, Temporal never refreshes and every rotation needs a temporal-frontend restart.
- plus `KEYS_RELOAD_INTERVAL`, since `serve` publishes a key generated by `tempogate keys generate` only on its next reload,
- plus up to 300 s if an HTTP cache that honours tempogate's `Cache-Control: max-age=300` sits between Temporal and `/.well-known/jwks.json` (raise the delay to `10m` in that case).

The default `5m` covers Temporal's default `1m` refresh and the default `30s` reload with margin.

### Rotation runbook

1. **Generate** a new key: `tempogate keys generate --force` (against the same `STATE_SQLITE_PATH`, e.g. `kubectl exec deploy/tempogate -- /tempogate keys generate --force`).
   The output says when it starts signing.
   `serve` publishes it in `/.well-known/jwks.json` within `KEYS_RELOAD_INTERVAL`; the old key keeps signing.
2. **Wait `KEYS_PUBLISH_DELAY`.** Relying parties fetch the new key; then it signs every new token.
   `tempogate keys list` and `GET /admin/signing-keys` show every key with its `created_at` and `retired_at`, which one is signing (`signing` / `"active": true`), and when a pending key starts signing (`pending, signs from ...` / `activates_at`).
3. **Retire** the old key once the new one signs: `tempogate keys retire <old-kid>` (a `kid` may start with `-`; no `--` needed), or `POST /admin/signing-keys/<old-kid>/retire` with the admin token.
   The only active key cannot be retired (409 / an error naming `keys generate --force`).
   Retiring the signing key while its replacement is still inside `KEYS_PUBLISH_DELAY` is refused (409 / an error naming the replacement and when it signs).
4. **Grace.** The retired key keeps verifying for `KEYS_RETIREMENT_GRACE`, then leaves JWKS.
   Tokens it signed stop working at tempogate at that moment and at Temporal after its next JWKS refresh.
   Users re-authenticate and get tokens from the new key; integration keys must be re-minted.

In an emergency (a leaked key) retire right after step 1 with `tempogate keys retire --force <old-kid>` or `POST /admin/signing-keys/<old-kid>/retire?force=true`.
The new key then signs at once, so Temporal rejects new tokens until its next JWKS refresh (at most `refreshInterval`); that is the price of stopping the leaked key immediately.
The grace still applies, so if 4 h is too long, lower `KEYS_RETIREMENT_GRACE` (it is read at `serve` start) before retiring.

### Upgrading to required key expiry

`POST /admin/keys` now refuses a body without `expires_at` (400), and `expires_at` may be at most `ADMIN_KEYS_MAX_TTL` (default 90 days) away.
Callers that relied on long-lived keys must send an expiry and re-mint before it.
Keys minted earlier without `expires_at` are not touched: their JWT has no `exp`, so they stay valid at Temporal until their signing key is retired.
To end them, run the rotation runbook above; `GET /admin/keys` lists them with no `expires_at`.
`tempogate migrate` adds the `retired_at` column (migration 0013) and leaves existing keys active.

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

## Observability

### Metrics

`GET /metrics` on the **admin listener** serves Prometheus metrics.
It is deliberately absent from the public listener (that returns 404) and sits outside `/admin/*`, so a scraper needs network access to the admin listener but no admin credentials.
It is also exempt from `ADMIN_ALLOWED_HOSTS`: Prometheus addresses a target by its pod IP, which an allowlist of names would refuse, and the response carries nothing a DNS-rebinding page could use (no identities, tokens or keys).
That makes the admin listener's bind the access control: keep it on loopback or a cluster-internal address restricted by a NetworkPolicy, never behind a public Service or Ingress.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `tempogate_logins_total` | counter | `result` (`success`, `failure`), `reason` | Completed Google sign-in callbacks. `reason` is `none` on success, else one of `missing_state`, `state_not_bound` (the callback came from another browser than the one that started the sign-in), `unknown_state`, `expired_request`, `upstream_denied`, `missing_code`, `upstream_error`, `email_unverified`, `domain_not_allowed`, `hosted_domain_not_allowed` (the `hd` claim failed [Workspace mode](#hosted-domain-workspace-mode)), `internal`. |
| `tempogate_tokens_issued_total` | counter | `grant` (`authorization_code`, `refresh_token`, `device_code`) | Tokens minted by `/token`. |
| `tempogate_token_errors_total` | counter | `grant` (as above, or `other`), `error` | Failed `/token` requests by OAuth2 error code (`invalid_request`, `invalid_grant`, `invalid_client`, `unauthorized_client`, `unsupported_grant_type`, `authorization_pending`, `slow_down`, `access_denied`, `expired_token`) or `server_error` for a 500. `invalid_client` is a confidential client that failed to authenticate. Device-flow polling counts `authorization_pending` on every poll. Requests the rate limiter rejects never reach `/token` and are counted in `tempogate_rate_limited_total` instead. |
| `tempogate_refresh_family_revocations_total` | counter | `event` (`auth_code_reuse`, `refresh_token_reuse`, `refresh_domain_not_allowed`) | Refresh-token families tempogate revoked on its own: a replayed authorization code or refresh token, or a refresh for an email domain no longer in `OIDC_ALLOWED_DOMAINS`. The refused request is also counted as `invalid_grant`. Operator revocations (`tempogate sessions revoke`, `POST /admin/sessions/revoke`) are not counted; the admin API's [audit log](#admin-api) records the latter. |
| `tempogate_rate_limited_total` | counter | `endpoint` (`authorize`, `device_authorization`, `device_verification`, `token`) | Requests answered `429` by the per-client [rate limits](#abuse-controls). The client address is never a label. |
| `tempogate_upstream_request_duration_seconds` | histogram | `op` (`discovery`, `code_exchange`, `verify_id_token`) | Latency of calls to Google, failed calls included. `verify_id_token` includes the JWKS fetch on a key-cache miss. `discovery` runs on first use and again on each retry after a failure; a failure served from inside the retry backoff is not a call and is not counted. |
| `tempogate_upstream_errors_total` | counter | `op`, `reason` (`timeout`, `error`) | Failed calls to Google. `timeout` is a call that got no answer within the [upstream timeout](#google-leg); `error` is any other failure, including an error answer from Google. |
| `tempogate_db_errors_total` | counter | `op` (the store operation, e.g. `consume_refresh`, `probe`, `reap`) | State-store operations that failed. A miss (unknown or replayed code or token) is not an error. |
| `tempogate_build_info` | gauge | `version`, `commit` | Always `1`; identifies the running build. |

The Go runtime (`go_*`) and process (`process_*`) collectors are exposed too.
Every label value comes from a fixed set chosen by tempogate: emails, client IDs, tokens and raw request input never become labels.

Tracing (OpenTelemetry) is not implemented yet.

### Request logs

With `LOG_REQUESTS=true` (the default) each request on either listener emits one structured line through the server logger:

```
INFO	http	http request	{"listener": "public", "method": "POST", "path": "/token", "status": 200, "duration": "3.1ms", "bytes": 1234, "remote_addr": "10.0.0.7:51234", "user_agent": "tempogate-cli/0.3.0", "request_id": "..."}
```

- **Allowlisted fields only.** The query string (OAuth codes, `state`, PKCE parameters), request headers (`Authorization`, cookies) and bodies (refresh tokens, client secrets) are never logged; `path` is the URL path alone.
- **`request_id`** is copied from the `X-Request-Id` response header when one is set, and omitted otherwise.
- **`remote_addr`** is the TCP peer. Behind a proxy that is the proxy; `X-Forwarded-For` is not logged, even from an `HTTP_TRUSTED_PROXIES` peer.
- **Not an audit log.** The admin API's `admin audit` and `admin request rejected` lines record who did what; the access log records only that a request happened, so it carries no caller, token fingerprint or Host.
- **Level.** Requests log at `info`, so they are an audit trail at the default `LOG_LEVEL`. Kubelet probes and scrapes (`/healthz`, `/readyz`, `/admin/healthz`, `/metrics`) log at `debug`: they arrive every few seconds per pod and would drown the real traffic.

### Health probes

- **`/healthz`** (liveness) only says the process serves HTTP. It never touches the state store: restarting cannot bring back a lost volume, it would only turn a storage outage into a crash loop.
- **`/readyz`** (readiness) is `503` until the public listener is bound, and on every call checks the state store with a 500 ms budget (inside the kubelet's default 1 s probe timeout). The check pings the serving connection and also opens the database file at `STATE_SQLITE_PATH` read-only and reads the schema table, because the long-lived connection keeps working on a file that has been deleted, truncated or replaced underneath it. While it fails, `/readyz` answers `503` with a generic body (the cause is logged at `warn` and counted in `tempogate_db_errors_total{op="probe"}`), so the pod leaves the Service endpoints until the store is back.

## See also

- [Helm chart values](../charts/tempogate/README.md#values) — the same
  settings as chart `values.yaml` keys, plus Secret wiring.
- [docs/getting-started.md](getting-started.md) — these settings in a working
  end-to-end context.
