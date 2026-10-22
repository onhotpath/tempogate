# Configuration reference

This page lists every tempogate setting, its default, and when you need it.

## How configuration is resolved

tempogate reads three layers, and the last layer wins:

1. **Built-in defaults**, shown in the [quick reference](#quick-reference) and the tables below.
2. **An optional YAML file.**
   Nested keys are normal YAML (`oidc: { issuer: ... }`).
   tempogate loads the first file that applies:
   - `--config <path>`, which every subcommand accepts (`tempogate --config /etc/tempogate.yaml serve`);
   - the `TEMPOGATE_CONFIG` environment variable;
   - `application.yaml` in the working directory, if present.
     tempogate does **not** search parent directories, so a file planted above the working directory cannot repoint the server.

   If tempogate cannot read a file named by `--config` or `TEMPOGATE_CONFIG`, it stops.
   If it cannot read `application.yaml` in the working directory, it logs a warning and skips the file.
   This occurs, for example, with the image's `/home/nonroot` when the container runs under a uid other than the default `65532`.
   Run with `LOG_LEVEL=debug` to log which file tempogate loaded.
3. **Environment variables.** They **override** the file.

Use environment variables for containers and Kubernetes.
Nested keys flatten with a **`_`** separator: `oidc.google.client_id` becomes `OIDC_GOOGLE_CLIENT_ID`.

## Quick reference

One row per setting, for a quick look.
The sections below give the full detail of each one.

**Minimum for real SSO:** `OIDC_ISSUER`, `OIDC_CLIENTS`, `OIDC_ALLOWED_DOMAINS`, `OIDC_SESSION_SIGNING_KEY`, `OIDC_GOOGLE_CLIENT_ID`, `OIDC_GOOGLE_CLIENT_SECRET`, and at least one `OIDC_AUTHZ_RULES_<n>` (or `OIDC_AUTHZ_DEFAULT_PERMISSIONS`).
If your users are in Google Workspace, also set `OIDC_ALLOWED_HOSTED_DOMAINS`.

| Env var | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | For real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer` and used to derive `jwks_uri`. Must be `https://` unless the host is loopback (see `OIDC_ALLOW_INSECURE_ISSUER`). May include a path (e.g. `https://host/idp`) - see [Sub-path hosting](#sub-path-hosting) |
| `OIDC_ALLOW_INSECURE_ISSUER` | No | `false` | Development only. `serve` refuses a plain-http `OIDC_ISSUER` unless its host is loopback (`localhost`, `127.0.0.0/8`, `::1`) or this is `true` |
| `OIDC_CLIENTS` | For any login | _(empty)_ | Comma-separated `id:redirect_uri` allowlist of **exact** redirect URIs (repeat an id for several). Loopback `http://127.0.0.1/<path>` entries match any port. Register the CLI as `tempogate-cli:http://127.0.0.1/callback` and the device CLI as `tempogate-device:` |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | No | `false` | Dev only: allow plain-`http` non-loopback redirect URIs in `OIDC_CLIENTS` (e.g. a local Docker Compose stack) |
| `OIDC_ALLOWED_DOMAINS` | For any login | _(empty)_ | Comma-separated email-domain gate applied after Google sign-in and again on every refresh |
| `OIDC_ALLOWED_HOSTED_DOMAINS` | Recommended | _(empty)_ | Comma-separated Google Workspace domains; when set, Google's `hd` claim must match ("Workspace mode"). See [Hosted domain (Workspace mode)](#hosted-domain-workspace-mode) |
| `OIDC_AUTHZ_RULES_<n>` | This or the next | _(none)_ | Indexed rules (`OIDC_AUTHZ_RULES_0`, `_1`, ...) `"<email:address\|domain:domain>=<namespace>:<role>[,...]"` mapping a signed-in person to Temporal permissions; re-applied on every refresh. See [Authorization](#authorization) |
| `OIDC_AUTHZ_DEFAULT_PERMISSIONS` | This or the previous | _(empty)_ | Comma-separated permissions for admitted people no rule matches; empty denies them. `serve` refuses to start with no rules and no default. `temporal-system:admin` keeps the pre-rules behaviour (logged as a warning) |
| `OIDC_ACCESS_TOKEN_TTL` | No | `4h` | Lifetime of each access token (ID tokens live 5 minutes) |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | No | `temporal` | `aud` of every access token and integration key; set Temporal's `global.authorization.audience` (v1.29.0+) to match. See [Access tokens and ID tokens](#access-tokens-and-id-tokens) |
| `OIDC_REFRESH_TOKEN_TTL` | No | `168h` (7 days) | Idle lifetime of each rotated refresh token |
| `OIDC_REFRESH_MAX_LIFETIME` | No | `168h` (7 days) | Absolute session lifetime from sign-in; rotation never extends it. See [Refresh-token sessions](#refresh-token-sessions) |
| `OIDC_GOOGLE_CLIENT_ID` | For any login | _(empty)_ | Upstream Google OAuth client |
| `OIDC_GOOGLE_CLIENT_SECRET` | For any login | _(empty)_ | Upstream Google OAuth client secret |
| `OIDC_SESSION_SIGNING_KEY` | Yes | _(empty)_ | Base64url 32-byte HMAC key for the device-flow session cookie and SSO `state`, and for deriving the Google leg's PKCE verifier, nonce and browser binding; `serve` refuses to boot without it |
| `OIDC_SESSION_TTL` | No | `5m` | Lifetime of the device-flow verification-page session cookie |
| `OIDC_GOOGLE_AUTH_ENDPOINT`, `OIDC_GOOGLE_TOKEN_ENDPOINT`, `OIDC_GOOGLE_ISSUER_URL` | No | Google's | Upstream endpoint overrides, for a mock IdP only |
| `OIDC_CLIENT_SECRETS` | No | _(empty)_ | Comma-separated `id:secret`; promotes a registered client to confidential (PKCE carve-out) |
| `HTTP_LISTENER` | No | `127.0.0.1:8000` | `host:port` for the public listener |
| `HTTP_TRUSTED_PROXIES` | Behind a reverse proxy | _(empty)_ | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` is trusted for the client address. See [Abuse controls](#abuse-controls) |
| `HTTP_RATE_LIMIT_AUTHORIZE`, `HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION`, `HTTP_RATE_LIMIT_DEVICE_VERIFICATION`, `HTTP_RATE_LIMIT_TOKEN` | No | `30`, `10`, `20`, `60` | Requests per minute per client address to `/authorize`, `/device_authorization`, `POST /device` and `/token`; `0` disables |
| `API_DOCS_ENABLED` | No | `false` | Dev only: serve the OpenAPI document and docs page on the public listener. `serve` refuses it unless `OIDC_ISSUER` is plain `http://` |
| `ADMIN_LISTENER` | No | `127.0.0.1:8081` | `host:port` for the separate admin listener (`/admin/*`, Prometheus `/metrics`); never expose it publicly |
| `ADMIN_TOKEN_SHA256` | To use the admin API | _(empty)_ | Comma-separated hex SHA-256 digests of accepted admin bearer tokens. Empty locks the admin API (401) |
| `ADMIN_ALLOWED_HOSTS` | For a non-loopback admin bind | loopback names on the `ADMIN_LISTENER` port | Comma-separated `host[:port]` accepted in `Host`; others get 421 (DNS-rebinding defence) |
| `ADMIN_ALLOW_SYSTEM_GRANTS` | No | `false` | Allow minting cluster-wide `temporal-system` keys (403 otherwise) |
| `ADMIN_KEYS_MAX_TTL` | No | `2160h` (90 days) | Furthest in the future an integration key's required `expires_at` may lie |
| `SERVER_READ_HEADER_TIMEOUT`, `SERVER_READ_TIMEOUT`, `SERVER_WRITE_TIMEOUT`, `SERVER_IDLE_TIMEOUT`, `SERVER_MAX_HEADER_BYTES`, `SERVER_SHUTDOWN_TIMEOUT` | No | `10s`, `15s`, `30s`, `60s`, `16384`, `15s` | HTTP server hardening for both listeners; see [HTTP server hardening](#http-server-hardening) |
| `STATE_DRIVER` | No | `sqlite` | State store backend: `sqlite` (one replica) or `postgres` (one or more). See [State store](#state-store) |
| `STATE_SQLITE_PATH` | No | `/var/lib/tempogate/state.db` | SQLite state-store path (back this with a PVC) |
| `STATE_SQLITE_MAX_CONNS` | No | `1` | SQLite connection pool size; do not raise (one writer) |
| `STATE_SQLITE_BUSY_TIMEOUT` | No | `5s` | How long a query waits on a locked database |
| `STATE_POSTGRES_DSN` / `STATE_POSTGRES_DSN_FILE` | With `STATE_DRIVER=postgres` | _(empty)_ | PostgreSQL 15+ connection string (or a file holding it, re-read per connection); a remote host needs `sslmode=verify-full`. See [PostgreSQL](#postgresql) |
| `STATE_POSTGRES_MAX_CONNS`, `STATE_POSTGRES_CONN_MAX_IDLE_TIME` | No | `10`, `30m` | Connection pool size per replica (at least 2) and idle timeout |
| `STATE_POSTGRES_LISTEN_DSN` | Behind a transaction-mode pooler | the main DSN | Direct connection for the change-notification `LISTEN` |
| `STATE_POSTGRES_ALLOW_INSECURE_SSLMODE` | No | `false` | Dev only: allow a non-loopback host without `sslmode=verify-full` |
| `STATE_REAPER_INTERVAL` | No | `5m` | How often `serve` deletes expired state; `0` disables |
| `KEYS_ENCRYPTION_KEY` / `KEYS_ENCRYPTION_KEY_FILE` | No | _(empty)_ | Base64 32-byte key (or a file holding it) that encrypts the stored signing key. See [Signing-key encryption](#signing-key-encryption) |
| `KEYS_RETIREMENT_GRACE` | No | `4h` | How long a retired signing key stays in JWKS and keeps verifying |
| `KEYS_RELOAD_INTERVAL` | No | `30s` | How often `serve` re-reads signing keys from the state store |
| `KEYS_PUBLISH_DELAY` | No | `5m` | How long a new signing key is published before it signs; must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`. See the [rotation runbook](#rotation-runbook) |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_REQUESTS` | No | `true` | One access-log line per HTTP request (no query strings, headers or bodies) |
| `TEMPOGATE_ISSUER` | No | _(empty)_ | **Client-side**, read by `tempogate login` (not the server). Equivalent to `--issuer` |
| `TEMPOGATE_LOGIN_MODE` | No | _(empty)_ | **Client-side**. `device` makes `tempogate login` use the device flow, as `--device` does; an explicit `--device` or `--device=false` wins |

## Environment variables

### Logging

| Variable | Default | Notes |
| --- | --- | --- |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `LOG_REQUESTS` | `true` | One structured access-log line per HTTP request on both listeners; see [Request logs](#request-logs). `false` turns it off, e.g. when an ingress or mesh already logs every request. |

### HTTP listener

| Variable | Default | Notes |
| --- | --- | --- |
| `HTTP_LISTENER` | `127.0.0.1:8000` | `host:port` for the single public listener (OIDC/OAuth2 + `/healthz` + `/readyz`). The loopback default is not reachable through a container or Service; set `0.0.0.0:8000` in a cluster. |
| `HTTP_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDRs or addresses of reverse proxies in front of tempogate. tempogate takes the client address from `X-Forwarded-For` only for a connection from one of these. See [Abuse controls](#abuse-controls). |
| `HTTP_RATE_LIMIT_AUTHORIZE` | `30` | Requests per minute per client address to `GET /authorize`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_AUTHORIZATION` | `10` | Requests per minute per client address to `POST /device_authorization`. `0` disables. |
| `HTTP_RATE_LIMIT_DEVICE_VERIFICATION` | `20` | Requests per minute per client address to `POST /device` (the user_code form). `0` disables. |
| `HTTP_RATE_LIMIT_TOKEN` | `60` | Requests per minute per client address to `POST /token`. `0` disables. |

### HTTP server hardening

The public and the admin listener use the same settings.
Durations are Go durations; `0` disables that timeout (not recommended).

| Variable | Default | Notes |
| --- | --- | --- |
| `SERVER_READ_HEADER_TIMEOUT` | `10s` | Time to read the request headers. Limits slow-header (slowloris) clients. |
| `SERVER_READ_TIMEOUT` | `15s` | Time to read the whole request, headers and body. Limits slow-body clients; request bodies are small form posts, capped at 1 MiB. |
| `SERVER_WRITE_TIMEOUT` | `30s` | Time from the end of the request headers until the response is written. It includes the handler, so it must be longer than the slowest legitimate request: the code exchange and JWKS fetch of the Google callback. No endpoint streams or long-polls (device-flow polling returns immediately). |
| `SERVER_IDLE_TIMEOUT` | `60s` | How long an idle keep-alive connection stays open between requests. |
| `SERVER_MAX_HEADER_BYTES` | `16384` | Maximum size of the request header block (net/http adds 4 KiB of slack). Larger requests get `431 Request Header Fields Too Large`. `0` uses the net/http default of 1 MiB. |
| `SERVER_SHUTDOWN_TIMEOUT` | `15s` | Time that in-flight requests get after `SIGTERM`. tempogate then force-closes connections that are still active (logged as `graceful shutdown: context deadline exceeded`); `0` force-closes at once. Keep it below the pod's `terminationGracePeriodSeconds` (Kubernetes default `30s`) and below the 1-minute stop limit of the process. |

### Abuse controls

The public endpoints accept anonymous requests, and `/authorize` and `/device_authorization` write a row per request.
tempogate thus limits the size and the rate of what an unauthenticated caller can send.

**Parameter caps.**
tempogate refuses an oversized parameter with `400 invalid_request` before it stores anything:

| Parameter | Maximum |
| --- | --- |
| `state`, `nonce` | 512 bytes |
| `scope` | 1 KiB |
| `client_id` | 256 bytes |
| `redirect_uri` | 2 KiB |
| `code_challenge` | Exactly 43 base64url characters (an S256 challenge) |
| `code`, `refresh_token`, `device_code`, `code_verifier` at `/token` | 1 KiB, well above the 43-character values that tempogate issues |

**Rate limits.**

- Each `HTTP_RATE_LIMIT_*` endpoint allows a burst of that many requests per client address, and refills evenly over one minute.
- IPv6 clients count per /64.
- A request over the budget gets `429 Too Many Requests` with `Retry-After` (seconds until one more request is allowed). On the OAuth endpoints the body is an RFC 6749 error, `{"error": "temporarily_unavailable", ...}`.
- The budgets are in process memory. They reset on restart, and each replica counts separately.
- To let a fronting proxy or WAF do the rate limit, set the matching limit to `0`.
- The Temporal Web UI calls `/token` from its server for the sign-in and refresh of every user. All UI users thus share the `/token` budget of the UI server; raise `HTTP_RATE_LIMIT_TOKEN` if many users sign in at the same time.

**Client address behind a proxy.**
By default, the client address is the TCP peer.
Behind an ingress or a load balancer, every request then comes from the proxy: all clients share one budget, and one noisy client can lock out everyone.
To prevent this, set `HTTP_TRUSTED_PROXIES` to the proxy addresses (for a Kubernetes ingress controller, usually the pod CIDR).
For a connection from a trusted proxy, tempogate reads `X-Forwarded-For` from the right and uses the first address that is not a trusted proxy.
It ignores the entries further left, because the client wrote them.
A connection from any other address is its own client, whatever `X-Forwarded-For` it sends.
Never list a range that clients can connect from directly, or they can choose their own budget.

### API documentation

| Variable | Default | Notes |
| --- | --- | --- |
| `API_DOCS_ENABLED` | `false` | Dev only. Serves the OpenAPI document (`/openapi.json`, `/openapi.yaml`), the docs page (`/docs`) and the JSON schemas (`/schemas/*`) on the public listener, under the OIDC base path. `serve` refuses to start with it on unless `OIDC_ISSUER` is plain `http://`, so an https deployment cannot enable it. The admin listener never serves them. When off, they return `404`, and response bodies have no `$schema` link. In all other cases, use `tempogate gen-oas` (public spec) and `tempogate gen-oas --admin` (admin spec), which always work. |

### Admin API

The admin API has its own listener, never the public one.
It serves `/admin/keys` for integration keys, `/admin/signing-keys` for [signing-key retirement](#revocation-and-signing-key-retirement), `/admin/sessions` for [refresh-token sessions](#refresh-token-sessions), and the `/admin/healthz` liveness probe.
Every `/admin/*` route except `/admin/healthz` requires `Authorization: Bearer <admin token>`.
The same listener serves Prometheus [`GET /metrics`](#metrics), outside `/admin/*` and with no token.
You configure only the SHA-256 digest of the token, so the token itself is never in env, YAML or a ConfigMap.

| Variable | Default | Notes |
| --- | --- | --- |
| `ADMIN_LISTENER` | `127.0.0.1:8081` | `host:port` for the admin listener. Keep it on loopback unless you must manage keys from another host; a non-loopback bind also needs `ADMIN_ALLOWED_HOSTS`. |
| `ADMIN_TOKEN_SHA256` | _(empty)_ | Comma-separated lowercase-hex SHA-256 digests of the accepted admin tokens. During a rotation, list two, then remove the old one. **Empty locks the admin API:** every route except `/admin/healthz` answers 401, and tempogate logs a startup warning. A malformed entry stops `serve` at boot. |
| `ADMIN_ALLOWED_HOSTS` | `127.0.0.1:<port>,localhost:<port>,[::1]:<port>` | Comma-separated `host[:port]` values accepted in the `Host` header; an entry without a port matches any port. Other hosts get **421 Misdirected Request** before the token check, which defeats DNS rebinding from a browser. The default takes `<port>` from `ADMIN_LISTENER` and names only loopback, even for a `0.0.0.0` bind: **set it to the names your callers use** (e.g. `tempogate-admin.tempogate.svc:8081`). |
| `ADMIN_ALLOW_SYSTEM_GRANTS` | `false` | Allow keys for the `temporal-system` namespace. Temporal treats a `temporal-system` role as cluster-wide, so these grants answer 403 unless this is `true`. Enable it only while you mint the keys that need it. |
| `ADMIN_KEYS_MAX_TTL` | `2160h` (90 days) | Go duration; the latest `expires_at` that an integration key can have. `expires_at` is required, and a value in the past or beyond this cap answers 400. Temporal ignores revocation, so this cap limits how long a leaked key works there, unless you [retire its signing key](#revocation-and-signing-key-retirement). Must be positive. |

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

tempogate logs each admin change as one `admin audit` line:

- A key mint or revoke has `action`, `outcome`, `id`, `jti`, `namespace`, `role`, `owner`, `caller` and `remote_addr`.
- A signing-key retirement has `action=retire_signing_key`, the `kid` and `force`.
- A session revoke has `action=revoke_sessions`, the selector (`email`, `subject` or `family_id`) and `revoked`, the number of live sessions it ended.

A rejected request logs `admin request rejected` at warn level, with a `reason`.
`caller` is the first 8 hex characters of the matched digest, so you can tell rotated tokens apart without logging them.

### Signing keys

| Variable | Default | Notes |
| --- | --- | --- |
| `KEYS_RETIREMENT_GRACE` | `4h` | Go duration; how long a retired signing key stays in `/.well-known/jwks.json` and keeps verifying. After it, no token signed by that key verifies, whatever its `exp` ([details](#revocation-and-signing-key-retirement)). The default equals the 4 h access-token TTL, so tokens minted just before a retirement live out their natural life. `0` unpublishes a key at retirement. Must not be negative. |
| `KEYS_RELOAD_INTERVAL` | `30s` | Go duration; how often `serve` re-reads signing keys from the state store, so `tempogate keys generate --force` and `tempogate keys retire` from another process apply with no restart. A retire through the admin API applies at once. Must be positive. |
| `KEYS_PUBLISH_DELAY` | `5m` | Go duration; how long a new signing key is in `/.well-known/jwks.json` before it signs. Until then the previous non-retired key signs; with no other non-retired key (fresh install, or every key retired) the new key signs at once. **Must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`** ([why](#why-new-keys-wait-before-signing)). `0` signs as soon as `serve` loads the key. Must not be negative. |

### State store

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_DRIVER` | `sqlite` | `sqlite` (one replica, a file on a volume) or `postgres` (one or more replicas on a shared PostgreSQL database). Every subcommand that opens the store (`serve`, `migrate`, `keys`, `sessions`) uses this setting. |
| `STATE_REAPER_INTERVAL` | `5m` | Go duration; how often `serve` deletes expired state (see below). `0` disables the reaper. |

Both backends hold the same data with the same guarantees (the contract in `state/doc.go`, checked against both by the `state/storetest` suite), and `tempogate migrate` creates or upgrades either schema.
You cannot yet move an installation from one backend to the other.

**Secrets at rest.**
Refresh tokens (consumed ones included), authorization codes, device codes and verification-page session ids are stored only as their SHA-256, so a database copy (a backup, a volume snapshot) holds nothing a client can present.
The device flow's `user_code` is the exception: it is short enough to reverse its hash by trying every code, and its approval needs a signed-in browser session anyway.

**Reaper.**
`serve` deletes expired rows every `STATE_REAPER_INTERVAL`, starting at boot:

- pending authorization requests, authorization codes, device codes and verification-page sessions, when they expire;
- denylisted integration-key ids, one hour after the key's `expires_at` (keys without one stay denylisted);
- refresh tokens, one whole session (family) at a time, only when every token in it is dead: the session is past `OIDC_REFRESH_MAX_LIFETIME`, or every token expired and was rotated or revoked.
  Until then tempogate keeps rotated tokens, so it still detects their reuse.

The reaper deletes in batches, so a large sweep does not delay sign-ins, and logs counts at `debug` and failures at `warn`.
With Postgres every replica runs it, and each batch skips rows that another replica (or a request) has locked, so they share the work with no coordination.

#### SQLite

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_SQLITE_PATH` | `/var/lib/tempogate/state.db` | Holds the signing keypair, auth codes, and refresh tokens (consumed ones included, kept to detect reuse). Use durable storage: if you lose it, the signing keys rotate and every issued refresh token becomes invalid. See below for how tempogate protects its contents. |
| `STATE_SQLITE_MAX_CONNS` | `1` | SQLite tolerates one writer. Do not raise it; for more than one replica, use `STATE_DRIVER=postgres`. |
| `STATE_SQLITE_BUSY_TIMEOUT` | `5s` | Go duration; how long a query waits on a locked database before it fails. |

The database file and its `-wal` / `-shm` companions are created with, and reset on every start to, mode `0600`, whatever the umask.
A missing state directory is created `0700`.
An existing directory, such as a mounted volume, stays as it is; tempogate warns if other users can enter it (group access, as a Kubernetes `fsGroup` grants, is expected and not reported).

Migration `0012` deletes the existing rows of the tables whose secrets became hashes, because SQLite cannot compute the hashes: every user signs in again after the upgrade.

#### PostgreSQL

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_POSTGRES_DSN` | _(empty)_ | Connection string, URL (`postgres://user:pass@host:5432/db?sslmode=verify-full`) or keyword/value form. Set this or `STATE_POSTGRES_DSN_FILE`, not both. |
| `STATE_POSTGRES_DSN_FILE` | _(empty)_ | Path to a file that holds the connection string (surrounding whitespace ignored), e.g. a mounted Kubernetes Secret. tempogate reads it again for each new connection, so a rotated password applies with no restart. It reads the pool settings below only at startup. |
| `STATE_POSTGRES_MAX_CONNS` | `10` | Connections per replica, at least `2`. Size the server's `max_connections` (or the pooler) for replicas × this, plus one LISTEN connection per replica. |
| `STATE_POSTGRES_CONN_MAX_IDLE_TIME` | `30m` | Go duration; tempogate closes pooled connections that stay idle for longer than this. |
| `STATE_POSTGRES_LISTEN_DSN` | the main DSN | Connection string for the one long-lived `LISTEN` connection of each replica (see below). Set it to reach Postgres directly when the main DSN goes through a transaction-mode pooler. |
| `STATE_POSTGRES_ALLOW_INSECURE_SSLMODE` | `false` | Development only: lets tempogate connect to a non-loopback host without `sslmode=verify-full`. Logs a warning at startup. |

PostgreSQL 15 is the minimum; CI tests 15 and 18, the oldest and newest majors with community support.
Managed services (RDS, Cloud SQL, Azure Database for PostgreSQL) work like any other server.
tempogate does not support CockroachDB or other Postgres-compatible databases.

Run `tempogate migrate` before `serve`, with a role that can create tables in the database's default schema; `serve`, `keys` and `sessions` only read and write rows.
Migrations run in one transaction under a Postgres advisory lock, so concurrent runs (replicas, init containers) apply each version once, and a failed migration leaves the schema as it was.

**Connection security.**
`serve`, `migrate` and every other subcommand refuse a connection string that can reach a remote server without authenticating it.
Every host must use `sslmode=verify-full`, with the server's CA available (`sslrootcert=/path/ca.pem`, or the system roots).
`require` and `verify-ca` encrypt but accept an impostor, and `prefer` (the libpq default) silently falls back to plain text.
Unix sockets and loopback hosts (`localhost`, `127.0.0.0/8`, `::1`) are exempt.
For development stacks, where the database is a container on a private network, `STATE_POSTGRES_ALLOW_INSECURE_SSLMODE=true` relaxes the check.
Also add `require_auth=scram-sha-256`, so a server (or an attacker in the middle) cannot downgrade the login to MD5 or a cleartext password:

```text
postgres://tempogate@db.example.com:5432/tempogate?sslmode=verify-full&sslrootcert=/etc/tempogate/db-ca.pem&require_auth=scram-sha-256
```

**Change notifications.**
Key generation, key retirement and integration-key revocation send a Postgres `NOTIFY` in the same transaction, and every replica holds one `LISTEN` connection.
All replicas thus reload keys and refuse a revoked integration key within moments, not within `KEYS_RELOAD_INTERVAL` and the 30 s denylist cache.
Token requests never notify.
A lost listener reconnects with backoff (logged at `warn`) and re-reads what it may have missed; the periodic reloads stay as a backstop, so changes can arrive later but are never lost.

**Behind PgBouncer.**

- In transaction pooling mode, set `max_prepared_statements` (PgBouncer 1.21 or later) to a non-zero value, or add `default_query_exec_mode=exec` to `STATE_POSTGRES_DSN`, because tempogate's driver prepares statements.
- Transaction pooling cannot hold a `LISTEN`, so point `STATE_POSTGRES_LISTEN_DSN` at the database directly (or at a session-mode pool).
- Migrations and first-boot key generation use transaction-level advisory locks, which work through a transaction pooler.

**Several replicas.**

- Every replica must share `OIDC_SESSION_SIGNING_KEY` and the rest of the configuration. You need no sticky sessions, because all flow state is in the database.
- On an empty database, replicas that start together generate one signing key between them.
- Each replica counts rate limits (`HTTP_RATE_LIMIT_*`) separately, so the effective limit is replicas × the configured value.
- The Helm chart does not offer this mode yet: it still runs one replica on SQLite.

### Signing-key encryption

| Variable | Default | Notes |
| --- | --- | --- |
| `KEYS_ENCRYPTION_KEY` | _(empty)_ | Base64-encoded 32-byte key-encryption key (KEK). When set, tempogate stores the private signing key AES-256-GCM encrypted under it, not as plain PEM. Generate it once with `openssl rand -base64 32` and supply it through a Secret. |
| `KEYS_ENCRYPTION_KEY_FILE` | _(empty)_ | Path to a file that holds the same base64 value (surrounding whitespace ignored), e.g. a mounted Kubernetes Secret. Set at most one of the two. |

Without a KEK, anyone who can read the database can mint tokens that Temporal accepts.
With one, the database alone is not enough: keep the KEK where database backups do not go.

- tempogate writes new keys (the first boot, `tempogate keys generate`) encrypted.
- Keys stored before you set the KEK keep working, and `tempogate serve` warns about them. Encrypt them once with `tempogate keys encrypt`, which is safe to repeat. In Kubernetes, run it in the serving pod, e.g. `kubectl exec deploy/tempogate -- /tempogate keys encrypt`.
- When a key is encrypted, `tempogate serve` refuses to start without the KEK, or with a different one, and tells you why.
  `tempogate keys generate`, `keys list` and `keys retire` also read the stored keys, so they need the same KEK. A running server keeps its loaded keys if a reload cannot open them.
- Encrypted rows are bound to their key id, so nobody can swap them between rows.
- There is no KEK rotation yet. If you lose the KEK, you lose the signing keys: remove the `keypairs` rows and restart to mint a new key. After that, no token issued before validates.
- A rollback to a release without KEK support fails at startup when a key is encrypted.

### OIDC — server identity and Google federation

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | for real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer`, and the base of `jwks_uri`. Can include a path ([sub-path hosting](#sub-path-hosting)). **Must be `https://`** unless the host is loopback (`localhost`, `127.0.0.0/8`, `::1`), or `tempogate serve` refuses to start. |
| `OIDC_ALLOW_INSECURE_ISSUER` | no | `false` | **Development only.** Lets `serve` start, with a warning, on a plain-http `OIDC_ISSUER` with a non-loopback host (e.g. the docker-compose demo's `http://tempogate:8000`). Over plain http, anyone on the path can substitute the discovery document and signing keys. `migrate`, `keys` and `version` never check the issuer. |
| `OIDC_CLIENTS` | for any login | _(empty)_ | Comma-separated `id:redirect_uri`; the first `:` splits the id from the URI. Each value is an **exact** redirect URI, never a prefix ([Redirect URI registration](#redirect-uri-registration)). Repeat an id for several URIs; an empty value (`tempogate-device:`) registers a device-only client. **Every client here is public, and PKCE is mandatory.** Register the loopback CLI as `tempogate-cli:http://127.0.0.1/callback`. The [device flow](cli-device-login.md) also needs `tempogate-device:` and `tempogate-device-ui:<issuer>/device/sso-callback`, and `serve` refuses to start without the latter. Invalid entries stop the server at startup. |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | no | `false` | Dev only. Allows plain-`http` non-loopback redirect URIs in `OIDC_CLIENTS` (e.g. `http://temporal-ui:8080/auth/sso/callback` in a local Docker Compose stack). Keep it off in production: anyone on the network can read a code sent over plain http. |
| `OIDC_CLIENT_SECRETS` | no | _(empty)_ | Comma-separated `id:secret`. A separate, auditable opt-in that makes a registered client **confidential** (the [PKCE carve-out](pkce-and-confidential-clients.md)): the Temporal Web UI, which does not implement PKCE, and `tempogate-device-ui`, tempogate's own client for the device verification page's Google SSO. An entry for an unregistered id fails fast. |
| `OIDC_ALLOWED_DOMAINS` | for any login | _(empty)_ | Comma-separated email domains, exact match, checked on Google's verified email at sign-in and on every [refresh](#refresh-token-sessions). **Empty admits nobody.** |
| `OIDC_ALLOWED_HOSTED_DOMAINS` | recommended | _(empty)_ | Comma-separated Google Workspace domains. When set, Google's `id_token` must have an `hd` claim in this list (exact, case-insensitive). See [Hosted domain (Workspace mode)](#hosted-domain-workspace-mode). |
| `OIDC_AUTHZ_RULES_<n>` | this or the next | _(none)_ | Indexed list (`OIDC_AUTHZ_RULES_0`, `OIDC_AUTHZ_RULES_1`, ...; YAML `oidc.authz.rules`) of rules `"<selector>=<namespace>:<role>[,...]"` that set the Temporal permissions of a person's access token. See [Authorization](#authorization). |
| `OIDC_AUTHZ_DEFAULT_PERMISSIONS` | this or the previous | _(empty)_ | Comma-separated permissions for admitted people that no rule matches; empty denies them. **`serve` refuses to start when this and the rules are both empty.** See [Upgrading to deny-by-default authorization](#upgrading-to-deny-by-default-authorization). |
| `OIDC_ACCESS_TOKEN_TTL` | no | `4h` | Go duration; access-token lifetime, and so the revoke lag at the Temporal frontend, which verifies tokens against the JWKS only. Must be shorter than `OIDC_REFRESH_TOKEN_TTL`. ID tokens always live 5 minutes. |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | no | `temporal` | The `aud` of every access token, integration keys included; match it in Temporal's `global.authorization.audience` ([Access tokens and ID tokens](#access-tokens-and-id-tokens)). Must not be empty. |
| `OIDC_REFRESH_TOKEN_TTL` | no | `168h` | Go duration (7 days); idle lifetime of each rotated refresh token. A session not refreshed for this long ends. Must not exceed `OIDC_REFRESH_MAX_LIFETIME`. |
| `OIDC_REFRESH_MAX_LIFETIME` | no | `168h` | Go duration (7 days); absolute session lifetime from the original sign-in, never extended by rotation. Every user goes back through Google at least this often, and, because refresh never calls Google, a user suspended upstream keeps an unrevoked session at most this long. At the defaults it equals `OIDC_REFRESH_TOKEN_TTL`, so it is the limit that ends a session. Not `OIDC_SESSION_TTL`, the device-flow page cookie. |
| `OIDC_SESSION_SIGNING_KEY` | yes | _(empty)_ | Base64url-encoded 32-byte HMAC key. Signs the [device flow](cli-device-login.md)'s page session cookie and SSO-bounce `state`, each under its own domain-separation label, and derives the [Google leg](#google-leg)'s PKCE verifier, nonce and browser-binding cookie. A rotation fails logins in flight (at most the 5-minute auth request lifetime). Generate once with `openssl rand -base64 32 \| tr '+/' '-_' \| tr -d '='`, keep it stable across rolling restarts, and supply it through a Secret. **tempogate refuses to boot** if it is empty, not base64url, or not 32 bytes decoded. |
| `OIDC_SESSION_TTL` | no | `5m` | Go duration; TTL of the [device flow](cli-device-login.md)'s verification-page cookie, which bounds an approval window. Its path is `/device` (`<issuer-path>/device` under [sub-path hosting](#sub-path-hosting)). It is `Secure` unless `OIDC_ISSUER` is plain `http://`, because browsers never send a `Secure` cookie back over http. |
| `OIDC_GOOGLE_CLIENT_ID` | for any login | _(empty)_ | Upstream Google OAuth client id. |
| `OIDC_GOOGLE_CLIENT_SECRET` | for any login | _(empty)_ | Upstream Google OAuth client secret. Supply it through a Secret; never commit it. |
| `OIDC_GOOGLE_AUTH_ENDPOINT` | no | `https://accounts.google.com/o/oauth2/v2/auth` | Override only to point the flow at a mock IdP (testing/examples). |
| `OIDC_GOOGLE_TOKEN_ENDPOINT` | no | `https://oauth2.googleapis.com/token` | Where the callback exchanges the code for Google's `id_token`. Override for a mock IdP. |
| `OIDC_GOOGLE_ISSUER_URL` | no | `https://accounts.google.com` | Expected `iss` of Google's `id_token`, and the discovery/JWKS base for its signature check. Override for a mock IdP. |

The [quick reference](#quick-reference) lists the minimum settings for real SSO.

**Device verification rate limits** have no configuration keys:

- The verification pages allow 20 failed user-code attempts per minute per client IP, and 5 per minute per verification session. The limits are in memory on each replica (see [docs/cli-device-login.md](cli-device-login.md#security-notes)).
- The client IP is the TCP peer; tempogate does not read `X-Forwarded-For` here. Behind a reverse proxy, all clients thus share the IP budget of the proxy: one client that spends it blocks code entry for the others for up to a minute. The per-session budget still applies.

### Hosted domain (Workspace mode)

`OIDC_ALLOWED_DOMAINS` checks only the domain of the email address.
That does not prove that your organization controls the Google account.
Anyone who can receive mail at an address can create a consumer Google account for it, and Google then reports `email_verified: true`.
Google recommends that you restrict access to an organization with the `hd` (hosted domain) claim.
Google sets it only for accounts that a Google Workspace or Cloud organization manages ([OpenID Connect docs](https://developers.google.com/identity/openid-connect/openid-connect)).

To require it, set `OIDC_ALLOWED_HOSTED_DOMAINS` to your Workspace primary domain (or several, comma-separated):

| Google account | `OIDC_ALLOWED_HOSTED_DOMAINS` empty | `OIDC_ALLOWED_HOSTED_DOMAINS=example.com` |
| --- | --- | --- |
| Workspace user `alice@example.com` (`hd=example.com`) | admitted | admitted |
| Consumer account for `alice@example.com` (no `hd`) | admitted | **rejected (403)** |
| Account in another Workspace (`hd=other.test`) with an allowed email | admitted | **rejected (403)** |

- All checks apply: `email_verified`, the email domain in `OIDC_ALLOWED_DOMAINS`, and the `hd` claim.
- `hd` is the primary domain of the organization. List it even when users sign in with a secondary or alias domain.
- Leave the setting empty only when your email is not on Google Workspace. tempogate then logs a warning at startup.
- tempogate also sends Google the `hd` request parameter (the domain when you configure one, `*` when several), so the account chooser shows the correct account. That parameter is only a UI hint, because the user can edit the request; the `hd` claim check is the control.

### Authorization

`OIDC_ALLOWED_DOMAINS` and [Workspace mode](#hosted-domain-workspace-mode) decide who can sign in.
Authorization rules decide what the access token of each person can do in Temporal, and **the default is deny**: a person that no rule grants anything gets no token.

```bash
OIDC_AUTHZ_RULES_0='email:alice@example.com=temporal-system:admin'
OIDC_AUTHZ_RULES_1='domain:example.com=orders:read,payments:read'
OIDC_AUTHZ_RULES_2='email:bob@example.com=orders:write'
```

or, in YAML:

```yaml
oidc:
  authz:
    rules:
      - "email:alice@example.com=temporal-system:admin"
      - "domain:example.com=orders:read,payments:read"
      - "email:bob@example.com=orders:write"
    default_permissions: ""
```

As for every list, the environment replaces the YAML list as a whole; it does not merge the entries.
In the Helm chart, set `authz.rules` and `authz.defaultPermissions`.

**Grammar.** A rule is `<selector>=<permission>[,<permission>...]`.

| Selector | Matches |
| --- | --- |
| `email:<address>` | The verified email of the signed-in Google account, exactly, case-insensitively. |
| `domain:<domain>` | The domain of that email, exactly (subdomains are other domains), case-insensitively. Without Workspace mode, a consumer Google account for an address at the domain also matches, so tempogate logs a warning for `domain:` rules when `OIDC_ALLOWED_HOSTED_DOMAINS` is empty. |

A permission is `<namespace>:<role>`, the shape of Temporal's `permissions` claim, with the role `read`, `write` or `admin`.
`temporal-system:<role>` grants that role on every namespace, and is the only way to grant cluster-level APIs such as `ListNamespaces`.
`group:` selectors (Google Workspace groups) are reserved, and tempogate refuses them for now.

**Semantics.**

- Every matching rule applies. tempogate merges their permissions, and a namespace that several rules name gets the highest role, in one claim entry.
- `OIDC_AUTHZ_DEFAULT_PERMISSIONS` applies only to an admitted person that no rule matches.
- An empty result is a denial, and tempogate mints no authorization code or token:
  - At sign-in, the Google callback sends the client `error=access_denied`. `tempogate login` prints it and exits.
  - The device verification page denies the device code, so `tempogate login --device` stops polling with `access_denied`.
  - On the device verification page, tempogate checks a sign-in session again before every approval.
- Only the access token has the permissions; the ID token never has them (see [Access tokens and ID tokens](#access-tokens-and-id-tokens)).
- Integration keys from the admin API do not go through the rules. Each has the one namespace and role that it was minted with.

**Startup checks.** `tempogate serve` refuses to start when:

- a rule or the default is malformed, uses an unknown selector or `group:`, or names the `*` namespace (Temporal treats it as a namespace literally named `*`; use `temporal-system`);
- a rule or the default grants `worker`;
- neither rules nor a default are configured.

`worker` grants nothing under Temporal's default authorizer.
Worker is below Reader in Temporal's role bitmask ([`roles.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/roles.go#L9-L12)), and every API except health checks needs at least Reader.
Task-queue polling needs Writer ([`getRequiredRole`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_authorizer.go#L67-L77)), so grant workers `write`.

At startup, tempogate also:

- logs how many rules grant a `temporal-system` role;
- warns about rules whose domain is not in `OIDC_ALLOWED_DOMAINS` (nobody they select can sign in);
- warns when the default grants a `temporal-system` role (`every admitted user is cluster admin` for `admin`).

**Changes take effect at the next refresh.**
Rules are configuration, so a change needs a restart.
After that, every refresh resolves the permissions again, after the [domain re-check](#refresh-token-sessions).
A narrower grant mints a narrower token, and an empty one revokes the whole session (`invalid_grant`, logged as a `refresh_authz_denied` warning with the family id and email).
Access tokens already issued keep their permissions until they expire, so a change reaches a signed-in user within `OIDC_ACCESS_TOKEN_TTL` (4h) after the restart.
To end someone's sessions at once, [revoke them](#refresh-token-sessions) with `tempogate sessions revoke --email <e>` or `POST /admin/sessions/revoke`; access tokens already issued stay valid.

**Check a rule set.**
`tempogate authz explain --email <e>` reads the same configuration as `serve`.
It prints the matching rules, whether the default applied, and the permissions that the access token gets (or that the sign-in is denied).
It also flags an email whose domain is not in `OIDC_ALLOWED_DOMAINS`.

```bash
$ tempogate authz explain --email alice@example.com
email:        alice@example.com
matched:      rule 0  email:alice@example.com=temporal-system:admin
              rule 1  domain:example.com=orders:read,payments:read
permissions:  orders:read,payments:read,temporal-system:admin
```

**Namespace-scoped users and the Temporal Web UI.**
Temporal grants `ListNamespaces` only through a `temporal-system:<role>` permission.
It is a cluster-scoped API, so the default authorizer checks only the system role for it ([`metadata.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/api/metadata.go#L73), [`default_authorizer.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_authorizer.go#L47-L57), unchanged since v1.25).
A user with only `orders:read` thus cannot list namespaces, and the namespace dropdown of the Web UI stays empty for them.
They open their namespace by URL (`https://<temporal-ui>/namespaces/orders/workflows`), or you set the default namespace of the UI (`TEMPORAL_DEFAULT_NAMESPACE` for the `temporalio/ui` image) to the namespace that most users work in.
Do not grant `temporal-system:read` to fix the dropdown: it is read access to every namespace, workflow payloads included.
Revisit this if Temporal adds a grant that lists namespaces without access to their contents.

### Upgrading to deny-by-default authorization

Releases without authorization rules gave every admitted person `temporal-system:admin`.
That is no longer the default: with no rules and no default, `tempogate serve` stops at startup with `authz: no authorization configured`.

- To keep the previous behaviour while you write rules, set `OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin` (chart: `authz.defaultPermissions: "temporal-system:admin"`).
  tempogate logs a warning at every start that every admitted user is cluster admin.
- To move to rules, list the people who need cluster admin with `email:` rules, grant everyone else what they need per namespace, and leave the default empty.
  Check the result with `tempogate authz explain --email <e>` before you restart.
- Existing sessions keep working: their next refresh mints a token with the new permissions, or ends the session if the person gets nothing.
  Access tokens issued before the upgrade keep `temporal-system:admin` until they expire (`OIDC_ACCESS_TOKEN_TTL`); a session revoke (`tempogate sessions revoke`, `POST /admin/sessions/revoke`) only stops their renewal.

### Token subject

The `sub` of every token that tempogate mints for a person is `<connector>:<upstream sub>`; for Google, `google:<Google sub>`.
The connector is the one that the person signed in through.
The upstream `sub` is an opaque, stable id that Google never reuses.
The token also has the connector alone in an `idp` claim (`google`), and `/userinfo` returns both.
The connector is part of the identity, because the same upstream `sub` at two identity providers is two people; Google is the only connector today.

The email is in the `email` claim (the ID token also has `email_verified: true`).
Do not key users on the email: Google can give an address again to a different account, which then gets the identity of the previous holder.
Temporal's default claim mapper authorizes from `permissions`, not `sub`.
Integration keys do not change: their `sub` is still the owner of the key, and they have no `idp` claim.

### Google leg

tempogate is itself an OAuth client of Google, and protects that leg independently of the downstream client.
Google is its one upstream connector (id `google`): the server keeps the state, browser binding and admission gates, and the connector speaks Google's protocol, so these protections apply to any future connector too.

- **PKCE and nonce.** Every redirect to Google has tempogate's own S256 `code_challenge` and `nonce`; the code exchange sends the matching `code_verifier`, and an `id_token` with another `nonce` is rejected. So a Google code or `id_token` from another login cannot be injected into this one. No Google Cloud console setting is needed.
- **Browser binding.** `/authorize` sets a short-lived (5 minutes), HttpOnly, `SameSite=Lax` cookie that binds the internal `state` to the browser that started the login. `/callback/google` refuses a `state` that arrives without it (`400 invalid_request`, logged as `state_not_bound_to_browser`), so an attacker cannot finish their own Google login in the browser of a victim. This covers the Web UI and CLI logins, and the device-flow verification page, which signs in through the same `/authorize`.
- **Cookie shape.** With an `https` issuer, the cookie is `__Host-tempogate_upstream_<id>`: `Secure`, `Path=/`, no `Domain`, so a sibling subdomain cannot plant one. Browsers refuse `__Host-` and `Secure` cookies over plain http. With an `http://` issuer (local or compose setups), it is thus an unprefixed `tempogate_upstream_<id>` scoped to the callback path (e.g. `/callback/google`, or `<issuer-path>/callback/google` under [sub-path hosting](#sub-path-hosting)). `<id>` is different for each login, so parallel logins in one browser do not collide.
- **Derived, not stored.** The verifier, nonce and cookie value are HMAC-SHA256 derivations of the connector id and the internal `state` under `OIDC_SESSION_SIGNING_KEY`. tempogate thus stores nothing new, and refuses a `state` started for one connector at the callback of another connector.
- **Discovery.** Google's discovery document is fetched on the first callback after boot and cached once it succeeds. A failure is retried on a later callback after a backoff from 1s, doubling up to 30s, so a transient outage heals with no restart.
- **Issuer check.** When Google names itself in the authorization response (`iss`, RFC 9207), the value must equal `OIDC_GOOGLE_ISSUER_URL`; any other issuer fails the sign-in.
- **Logging.** A failed Google sign-in (`502 upstream_error` for the user) logs one warning with `op=oidc.callback`, `connector=google` and a `cause`: `discovery_unavailable`, `code_exchange_failed` (plus the token endpoint's `oauth_error`, e.g. `invalid_grant`), `id_token_invalid`, `nonce_mismatch`, `claims_incomplete` or `issuer_mismatch`. It adds `timeout=true` when a call or the whole callback got no answer in time. tempogate never logs codes or tokens.
- **Upstream timeout.** Each call to Google (discovery, code exchange, id_token verification with its JWKS fetch) times out after 10 seconds, 5 of them for connect and TLS handshake, and the whole callback after 25 seconds, under the 30-second `SERVER_WRITE_TIMEOUT`. A stalled Google fails the sign-in with the same `502 upstream_error` instead of a hung callback or a reset connection. A discovery timeout is retried after the usual backoff, never cached. These limits are fixed.

### Access tokens and ID tokens

`/token` returns two different JWTs, both signed with the keys published at `/.well-known/jwks.json`:

| | `access_token` | `id_token` |
| --- | --- | --- |
| For | Temporal (gRPC frontend, Web UI API calls, `tempogate token`) | the relying party's login only ([OIDC Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken)) |
| JWS `typ` | `at+jwt` ([RFC 9068](https://datatracker.ietf.org/doc/html/rfc9068)) | `JWT` |
| `aud` | `OIDC_ACCESS_TOKEN_AUDIENCE` (`temporal`) | the requesting `client_id` |
| Claims | `sub`, `idp`, `email`, `permissions`, `client_id` | `sub`, `idp`, `email`, `email_verified`, `auth_time`, `nonce` (when sent at `/authorize`) |
| Lifetime | `OIDC_ACCESS_TOKEN_TTL` (`4h`) | 5 minutes |

The ID token has no `permissions` claim, and Temporal's default ClaimMapper grants roles only from `permissions`, so Temporal refuses an ID token.
A relying party that receives or leaks an ID token holds nothing that Temporal authorizes.
Integration keys from the admin API are access tokens with the same `typ` and `aud` (no `client_id`).
`/userinfo` accepts only access tokens for `OIDC_ACCESS_TOKEN_AUDIENCE`; it refuses ID tokens, tokens for another audience, and tokens minted before this split.

**Temporal Web UI.**
The UI already sends the access token as its bearer, and the ID token only in the `Authorization-Extras` header, which Temporal's default ClaimMapper ignores (temporalio/ui v2.32.0, `src/lib/utilities/request-from-api.ts`).
No UI setting changes.
Do not configure a custom ClaimMapper that authorizes from `Authorization-Extras`.

**Temporal audience (defense in depth).**
Temporal v1.29.0 added `global.authorization.audience` ([temporalio/temporal#8067](https://github.com/temporalio/temporal/pull/8067)); when it is set, the frontend refuses any token whose `aud` does not contain it.
Set it to `OIDC_ACCESS_TOKEN_AUDIENCE` in the server config (no environment variable templates it):

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

Temporal v1.28 and earlier (including the `1.25.2` that the examples and e2e tests run) have no audience setting and ignore `aud`; they keep working with any value.
When Temporal enforces the audience, integration keys minted before this release (no `aud`) stop working, and you must mint them again.

### Refresh-token sessions

Each sign-in starts a session: a family of single-use refresh tokens that rotate on every exchange.
tempogate refuses a refresh with `invalid_grant` when:

- the session is idle for longer than `OIDC_REFRESH_TOKEN_TTL`, or older than `OIDC_REFRESH_MAX_LIFETIME`;
- the session is revoked;
- the email domain is no longer in `OIDC_ALLOWED_DOMAINS` (logs `refresh_domain_not_allowed`);
- the [authorization rules](#authorization) no longer grant the person anything (logs `refresh_authz_denied`);
- the connector that the person signed in through is no longer configured (logs `refresh_connector_removed`).

The last three cases also revoke the family.
A token that was already rotated revokes the whole family too ([RFC 9700 §4.14.2](https://datatracker.ietf.org/doc/html/rfc9700#section-4.14.2)), and logs a `refresh_token_reuse` warning with `family_id`, `client_id` and `email`.
tempogate never logs token values.

Operators manage sessions with the server binary, with the same state store settings as `serve`:

```bash
tempogate sessions list [--email alice@example.com] [--subject google:<sub>]   # family id, client, email, token sub, sign-in, last rotation, expiry
tempogate sessions revoke --email alice@example.com   # every session of a user
tempogate sessions revoke --subject google:<sub>      # every session of a Google account, whatever its email
tempogate sessions revoke --family <family-id>        # one session; fails if no such session exists
```

In Kubernetes, run them in the serving pod, e.g. `kubectl exec deploy/tempogate -- /tempogate sessions revoke --email alice@example.com`.
The [admin API](#admin-api) offers the same operations over HTTP, with no exec into the pod:

```bash
curl -H "Authorization: Bearer $token" 'http://127.0.0.1:8081/admin/sessions?email=alice@example.com'   # also ?subject=
curl -H "Authorization: Bearer $token" -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com"}' http://127.0.0.1:8081/admin/sessions/revoke   # or {"subject":...} or {"family_id":...}
```

- `GET /admin/sessions` returns `{"items": [...]}` with `family_id`, `client_id`, `email`, `subject`, `connector`, `auth_time`, `last_rotation_at` and `expires_at`. It never returns a token or its hash.
- `POST /admin/sessions/revoke` takes exactly one of `email`, `subject` or `family_id` (anything else is 400), and answers `{"revoked": <n>}`, the number of live sessions it ended.
- A `subject`, as a filter or a selector, is the token's `sub` in the form `<connector>:<upstream sub>` (e.g. `google:1234`), exactly as the list shows it. tempogate refuses a bare upstream `sub` with 400, and `--subject` on the command line refuses it too.
- Revocation is idempotent: a selector that matches nothing live answers 0. The exception is a `family_id` that never existed, which answers 404, like an unknown integration key.

Revocation stops refreshes at once.
Access tokens already issued stay valid, at tempogate's `/userinfo` and at Temporal, until they expire (`OIDC_ACCESS_TOKEN_TTL`).
The integration-key jti denylist does not apply to refresh tokens.

tempogate refuses a second redemption of an authorization code, and revokes the session that the first redemption started ([RFC 6749 §4.1.2](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2)); it logs `auth_code_reuse`.
tempogate keeps redeemed codes (hashed) until they expire, so it recognises a replay.
The access token already issued stays valid at Temporal until it expires.

**Upgrades.**

- Migration `0011` keeps existing sessions. Each existing refresh token becomes its own family, with its sign-in time set to its last refresh, so it ends at most `OIDC_REFRESH_MAX_LIFETIME` later.
- The default `OIDC_REFRESH_MAX_LIFETIME` was 30 days (`720h`) before it became 7 days. With the default, an upgrade ends every session signed in more than 7 days ago at its next refresh (`invalid_grant`), and those users sign in again. To keep the old lifetime, set `OIDC_REFRESH_MAX_LIFETIME=720h`.

### Redirect URI registration

`/authorize` sends a code only to a `redirect_uri` that matches a registered value, as [RFC 9700 §2.1](https://datatracker.ietf.org/doc/html/rfc9700#section-2.1) and [RFC 8252 §7.3](https://datatracker.ietf.org/doc/html/rfc8252#section-7.3) recommend.

| Entry | Kind | Matches |
| --- | --- | --- |
| `temporal-ui:https://temporal.example.com/auth/sso/callback` | exact | Only that exact string. No case, percent-encoding, trailing-slash or `..` variations. |
| `tempogate-cli:http://127.0.0.1/callback` | loopback | `http://127.0.0.1:<any port>/callback`, with no query. Also `http://[::1]/<path>`. `localhost` is **not** loopback: it gets exact matching. |
| `tempogate-device:` | device-only | Nothing at `/authorize`. The client can only use the device authorization grant (and refresh). |

Rules for each registered URI:

- It must be absolute, with a host and a path, and no userinfo or fragment.
- A loopback entry must omit the port, because any port is accepted.
- A non-loopback entry must use `https`, unless `OIDC_ALLOW_INSECURE_REDIRECT_URIS=true`.
- A client with redirect URIs cannot use `/device_authorization`, and a device-only entry cannot share its id with redirect URI entries.
- tempogate rejects prefix-shaped values from older releases (`tempogate-cli:http://127.0.0.1:`, `ui:https://ui.example.com`) at startup, with an error that names the entry.

The browser shows `/authorize` errors as JSON when they occur before tempogate validates the client and `redirect_uri` (unknown client, unregistered URI, oversized parameters).
tempogate sends later errors (an unsupported `response_type`, a missing `openid` scope, missing or malformed PKCE) back to the client's `redirect_uri` as `error` and `error_description`, with the client's `state` ([RFC 6749 §4.1.2.1](https://datatracker.ietf.org/doc/html/rfc6749#section-4.1.2.1)).
Every authorization response, success or error, has `iss` ([RFC 9207](https://datatracker.ietf.org/doc/html/rfc9207)), as discovery advertises with `authorization_response_iss_parameter_supported`.

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

Retiring a signing key is the hard kill switch: it invalidates **every** token that the key signed (human tokens, CLI tokens, integration keys), not one key.
Use it when a key leaked and its `exp` is too far away, or for routine rotation.
The `kid` of a token is in its JWT header.

### Why new keys wait before signing

Temporal's JWT key provider looks up the `kid` of a token only in the JWKS from its last refresh, and does not fetch again on an unknown `kid`.
See [`common/authorization/default_token_key_provider.go`](https://github.com/temporalio/temporal/blob/v1.25.2/common/authorization/default_token_key_provider.go): `RsaKey` returns "RSA key not found" from the cached map, and only the `refreshInterval` ticker calls `updateKeys`.
If tempogate signed with a new key at once, temporal-frontend would reject every token minted before its next refresh: login appears to succeed, but Temporal calls fail.

tempogate thus publishes a new key in JWKS at once, but signs with it only from `created_at + KEYS_PUBLISH_DELAY`.
Set `KEYS_PUBLISH_DELAY` above the longest time that Temporal can need to see a new key, which is the sum of:

- Temporal's `global.authorization.jwtKeyProvider.refreshInterval` (`TEMPORAL_JWT_KEY_REFRESH` in Temporal's Docker config template, default `1m`; `server.config.authorization.jwtKeyProvider.refreshInterval` in the Temporal Helm chart, see [`examples/kind/temporal-values.yaml`](../examples/kind/temporal-values.yaml)).
  With `refreshInterval` unset or `0`, Temporal never refreshes, and every rotation needs a temporal-frontend restart.
- `KEYS_RELOAD_INTERVAL`, because `serve` publishes a key from `tempogate keys generate` only on its next reload;
- up to 300 s if an HTTP cache that obeys tempogate's `Cache-Control: max-age=300` is between Temporal and `/.well-known/jwks.json` (in that case, raise the delay to `10m`).

The default `5m` covers Temporal's default `1m` refresh and the default `30s` reload, with margin.

### Rotation runbook

1. **Generate** a new key: `tempogate keys generate --force`, on the same state store (e.g. `kubectl exec deploy/tempogate -- /tempogate keys generate --force`).
   The output tells when it starts to sign.
   `serve` publishes it in `/.well-known/jwks.json` within `KEYS_RELOAD_INTERVAL`, and the old key keeps signing.
2. **Wait `KEYS_PUBLISH_DELAY`.** Relying parties fetch the new key, and then it signs every new token.
   `tempogate keys list` and `GET /admin/signing-keys` show every key with its `created_at` and `retired_at`, the key that signs (`signing` / `"active": true`), and when a pending key starts to sign (`pending, signs from ...` / `activates_at`).
3. **Retire** the old key after the new one signs: `tempogate keys retire <old-kid>` (a `kid` can start with `-`; no `--` needed), or `POST /admin/signing-keys/<old-kid>/retire` with the admin token.
   You cannot retire the only active key (409 / an error that names `keys generate --force`).
   You cannot retire the signing key while its replacement is still inside `KEYS_PUBLISH_DELAY` (409 / an error that names the replacement and when it signs).
4. **Grace.** The retired key keeps verifying for `KEYS_RETIREMENT_GRACE`, then leaves JWKS.
   Tokens that it signed then stop working at tempogate, and at Temporal after its next JWKS refresh.
   Users sign in again and get tokens from the new key; integration keys must be minted again.

**Emergency (a leaked key).**
Retire right after step 1 with `tempogate keys retire --force <old-kid>` or `POST /admin/signing-keys/<old-kid>/retire?force=true`.
The new key then signs at once, so Temporal rejects new tokens until its next JWKS refresh (at most `refreshInterval`); that is the cost of an immediate stop of the leaked key.
The grace still applies: if 4 h is too long, lower `KEYS_RETIREMENT_GRACE` before you retire (`serve` reads it at start).

### Upgrading to required key expiry

`POST /admin/keys` now refuses a body without `expires_at` (400), and `expires_at` can be at most `ADMIN_KEYS_MAX_TTL` (default 90 days) in the future.
Callers that relied on long-lived keys must send an expiry, and mint again before it.
tempogate does not change keys minted earlier without `expires_at`: their JWT has no `exp`, so they stay valid at Temporal until you retire their signing key.
To end them, follow the rotation runbook above; `GET /admin/keys` lists them with no `expires_at`.
`tempogate migrate` adds the `retired_at` column (migration 0013), and keeps existing keys active.

## Sub-path hosting

`OIDC_ISSUER` can contain a path, so tempogate can share a hostname with another app:

```
OIDC_ISSUER=https://tempogate.example.com/idp
```

The **entire OIDC surface** then serves under that prefix (`/idp/.well-known/openid-configuration`, `/idp/authorize`, `/idp/token`, `/idp/userinfo`, `/idp/callback/google`, …).
The discovery document advertises issuer-relative endpoints, so the `iss` claim, the advertised endpoints and the served routes always agree.
At your proxy, route the prefix to tempogate and **strip nothing**: tempogate owns the prefix natively.

- **Health probes stay at the root.** `/healthz` and `/readyz` do *not* move under the prefix, because they are infrastructure probes, not part of the public OIDC surface. Point Kubernetes liveness and readiness probes at `/healthz` and `/readyz`, whatever the issuer path. You do not need to route them through the shared-host proxy.
- **The Google redirect URI must include the prefix.** Register `https://tempogate.example.com/idp/callback/google` (issuer + `/callback/google`) in the Google OAuth client. See [examples/google-oauth-setup.md](../examples/google-oauth-setup.md).
- **The device-flow session cookie follows the prefix.** Its path is `/idp/device`, so the proxy must keep the path as it is.

A root issuer (no path) behaves as it always did.

## Security headers

Every response from both listeners has these headers:

| Header | Value |
| --- | --- |
| `Content-Security-Policy` | `default-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `no-referrer` |

Some pages replace the defaults with their own, and all of them keep `frame-ancestors 'none'`:

- The device verification pages send their own CSP. It allows their inline stylesheet by hash and, on the code entry page, adds the origin of the upstream IdP to `form-action`. They also send `Referrer-Policy: same-origin`: under `no-referrer`, the browser sends `Origin: null` on the Approve/Deny POST, and the origin check rejects it.
- With `API_DOCS_ENABLED=true`, `/docs` sends Huma's own CSP, which allows the renderer script and stylesheet that it loads from `unpkg.com`.

tempogate does not send `Strict-Transport-Security`.
TLS terminates at your proxy or ingress, which knows if the hostname is HTTPS-only, so set HSTS there.
Keep the headers above at the proxy: the anti-framing protection of the device approval page depends on them.

The public `/healthz` answers only `{"status":"ok"}`.
The build version is on `/admin/healthz` of the admin listener, and in the output of `tempogate version`.

## Observability

### Metrics

The **admin listener** serves Prometheus metrics at `GET /metrics`.
The public listener does not serve them (it returns 404), by design.
The endpoint is outside `/admin/*`, so a scraper needs network access to the admin listener, but no admin credentials.
`ADMIN_ALLOWED_HOSTS` does not apply to it: Prometheus addresses a target by its pod IP, which a list of names refuses, and the response has nothing that a DNS-rebinding page can use (no identities, tokens or keys).
The bind address of the admin listener is thus the access control.
Keep it on loopback, or on a cluster-internal address that a NetworkPolicy restricts; never put it behind a public Service or Ingress.

| Metric | Type | Labels | Meaning |
| --- | --- | --- | --- |
| `tempogate_logins_total` | counter | `result` (`success`, `failure`), `reason` | Completed Google sign-in callbacks. `reason` is `none` on success, else one of `missing_state`, `state_not_bound` (the callback came from another browser than the one that started the sign-in), `unknown_state`, `expired_request`, `connector_mismatch` (the sign-in was started for another connector), `upstream_denied`, `missing_code`, `upstream_error`, `email_unverified`, `domain_not_allowed`, `hosted_domain_not_allowed` (the `hd` claim failed [Workspace mode](#hosted-domain-workspace-mode)), `authz_denied` (admitted, but no [authorization rule](#authorization) grants anything; sent back as `access_denied`), `internal`. |
| `tempogate_tokens_issued_total` | counter | `grant` (`authorization_code`, `refresh_token`, `device_code`) | Tokens minted by `/token`. |
| `tempogate_token_errors_total` | counter | `grant` (as above, or `other`), `error` | Failed `/token` requests by OAuth2 error code (`invalid_request`, `invalid_grant`, `invalid_client`, `unauthorized_client`, `unsupported_grant_type`, `authorization_pending`, `slow_down`, `access_denied`, `expired_token`) or `server_error` for a 500. `invalid_client` is a confidential client that failed to authenticate. Device-flow polling counts `authorization_pending` on every poll. Requests the rate limiter rejects never reach `/token` and are counted in `tempogate_rate_limited_total` instead. |
| `tempogate_authz_denied_total` | counter | `stage` (`login`, `device_verification`, `authorization_code`, `refresh_token`, `device_code`) | Admitted people refused because no [authorization rule](#authorization) grants them anything: at the Google callback, on the device verification page, or at `/token` for the grant named (a rule removed after sign-in). The `login` refusals are also in `tempogate_logins_total{reason="authz_denied"}` and the `refresh_token` ones in `tempogate_refresh_family_revocations_total{event="refresh_authz_denied"}`. |
| `tempogate_refresh_family_revocations_total` | counter | `event` (`auth_code_reuse`, `refresh_token_reuse`, `refresh_domain_not_allowed`, `refresh_authz_denied`, `refresh_connector_removed`) | Refresh-token families tempogate revoked on its own: a replayed authorization code or refresh token, a refresh for an email domain no longer in `OIDC_ALLOWED_DOMAINS`, one the authorization rules no longer grant anything, or one whose sign-in connector is no longer configured. The refused request is also counted as `invalid_grant`. Operator revocations (`tempogate sessions revoke`, `POST /admin/sessions/revoke`) are not counted; the admin API's [audit log](#admin-api) records the latter. |
| `tempogate_rate_limited_total` | counter | `endpoint` (`authorize`, `device_authorization`, `device_verification`, `token`) | Requests answered `429` by the per-client [rate limits](#abuse-controls). The client address is never a label. |
| `tempogate_upstream_request_duration_seconds` | histogram | `op` (`discovery`, `code_exchange`, `verify_id_token`) | Latency of calls to Google, failed calls included. `verify_id_token` includes the JWKS fetch on a key-cache miss. `discovery` runs on first use and again on each retry after a failure; a failure served from inside the retry backoff is not a call and is not counted. |
| `tempogate_upstream_errors_total` | counter | `op`, `reason` (`timeout`, `error`) | Failed calls to Google. `timeout` is a call that got no answer within the [upstream timeout](#google-leg); `error` is any other failure, including an error answer from Google. |
| `tempogate_db_errors_total` | counter | `op` (the store operation, e.g. `consume_refresh`, `probe`, `reap`) | State-store operations that failed. A miss (unknown or replayed code or token) is not an error. |
| `tempogate_build_info` | gauge | `version`, `commit` | Always `1`; identifies the running build. |

The Go runtime (`go_*`) and process (`process_*`) collectors are also exposed.
tempogate takes every label value from a fixed set: emails, client IDs, tokens and raw request input never become labels.

Tracing (OpenTelemetry) is not implemented yet.

### Request logs

With `LOG_REQUESTS=true` (the default), each request on either listener writes one structured line through the server logger:

```
INFO	http	http request	{"listener": "public", "method": "POST", "path": "/token", "status": 200, "duration": "3.1ms", "bytes": 1234, "remote_addr": "10.0.0.7:51234", "user_agent": "tempogate-cli/0.3.0", "request_id": "..."}
```

- **Allowlisted fields only.** tempogate never logs the query string (OAuth codes, `state`, PKCE parameters), request headers (`Authorization`, cookies) or bodies (refresh tokens, client secrets). `path` is only the URL path.
- **`request_id`** is a copy of the `X-Request-Id` response header when one is set; otherwise it is absent.
- **`remote_addr`** is the TCP peer, which behind a proxy is the proxy. tempogate does not log `X-Forwarded-For`, even from an `HTTP_TRUSTED_PROXIES` peer.
- **Not an audit log.** The `admin audit` and `admin request rejected` lines of the admin API record who did what. The access log records only that a request occurred, so it has no caller, token fingerprint or Host.
- **Level.** Requests log at `info`, so they are a request trail at the default `LOG_LEVEL`. Kubelet probes and scrapes (`/healthz`, `/readyz`, `/admin/healthz`, `/metrics`) log at `debug`, because they arrive every few seconds per pod and would hide the real traffic.

### Health probes

- **`/healthz`** (liveness) only tells that the process serves HTTP. It never touches the state store: a restart cannot bring back a lost volume, and would only turn a storage outage into a crash loop.
- **`/readyz`** (readiness) is `503` until the public listener is bound. On every call, it checks the state store with a 500 ms budget (inside the kubelet's default 1 s probe timeout):
  - With SQLite, it pings the serving connection, and also opens the database file at `STATE_SQLITE_PATH` read-only and reads the schema table. The long-lived connection keeps working on a file that was deleted, truncated or replaced, so the ping alone is not sufficient.
  - With Postgres, it reads the schema table over a pooled connection.

  While the check fails, `/readyz` answers `503` with a generic body (the cause is logged at `warn` and counted in `tempogate_db_errors_total{op="probe"}`), so the pod leaves the Service endpoints until the store is back.

## See also

- [Helm chart values](../charts/tempogate/README.md#values) - the same settings as chart `values.yaml` keys, plus Secret wiring.
- [docs/getting-started.md](getting-started.md) - these settings in a working end-to-end context.
