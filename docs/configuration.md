# Configuration reference

This page lists every tempogate setting, its default, and when you need it.
The topic pages explain the behaviour behind the settings:

- [Authorization](authorization.md): Workspace mode, authorization rules and the token subject.
- [Operations](operations.md): sessions, revocation, key rotation and observability.
- [Hardening](hardening.md): abuse controls, security headers and signing-key encryption.
- [Upgrading](upgrading.md): what to change when you upgrade.

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
| `OIDC_ALLOWED_HOSTED_DOMAINS` | Recommended | _(empty)_ | Comma-separated Google Workspace domains; when set, Google's `hd` claim must match ("Workspace mode"). See [Hosted domain (Workspace mode)](authorization.md#hosted-domain-workspace-mode) |
| `OIDC_AUTHZ_RULES_<n>` | This or the next | _(none)_ | Indexed rules (`OIDC_AUTHZ_RULES_0`, `_1`, ...) `"<email:address\|domain:domain>=<namespace>:<role>[,...]"` mapping a signed-in person to Temporal permissions; re-applied on every refresh. See [Authorization](authorization.md#authorization) |
| `OIDC_AUTHZ_DEFAULT_PERMISSIONS` | This or the previous | _(empty)_ | Comma-separated permissions for admitted people no rule matches; empty denies them. `serve` refuses to start with no rules and no default. `temporal-system:admin` keeps the pre-rules behaviour (logged as a warning) |
| `OIDC_ACCESS_TOKEN_TTL` | No | `4h` | Lifetime of each access token (ID tokens live 5 minutes) |
| `OIDC_ACCESS_TOKEN_AUDIENCE` | No | `temporal` | `aud` of every access token and integration key; set Temporal's `global.authorization.audience` (v1.29.0+) to match. See [Access tokens and ID tokens](#access-tokens-and-id-tokens) |
| `OIDC_REFRESH_TOKEN_TTL` | No | `168h` (7 days) | Idle lifetime of each rotated refresh token |
| `OIDC_REFRESH_MAX_LIFETIME` | No | `168h` (7 days) | Absolute session lifetime from sign-in; rotation never extends it. See [Refresh-token sessions](operations.md#refresh-token-sessions) |
| `OIDC_GOOGLE_CLIENT_ID` | For any login | _(empty)_ | Upstream Google OAuth client |
| `OIDC_GOOGLE_CLIENT_SECRET` | For any login | _(empty)_ | Upstream Google OAuth client secret |
| `OIDC_SESSION_SIGNING_KEY` | Yes | _(empty)_ | Base64url 32-byte HMAC key for the device-flow session cookie and SSO `state`, and for deriving the Google leg's PKCE verifier, nonce and browser binding; `serve` refuses to boot without it |
| `OIDC_SESSION_TTL` | No | `5m` | Lifetime of the device-flow verification-page session cookie |
| `OIDC_GOOGLE_AUTH_ENDPOINT`, `OIDC_GOOGLE_TOKEN_ENDPOINT`, `OIDC_GOOGLE_ISSUER_URL` | No | Google's | Upstream endpoint overrides, for a mock IdP only |
| `OIDC_CLIENT_SECRETS` | No | _(empty)_ | Comma-separated `id:secret`; promotes a registered client to confidential (PKCE carve-out) |
| `HTTP_LISTENER` | No | `127.0.0.1:8000` | `host:port` for the public listener |
| `HTTP_TRUSTED_PROXIES` | Behind a reverse proxy | _(empty)_ | Comma-separated CIDRs or addresses of proxies whose `X-Forwarded-For` is trusted for the client address. See [Abuse controls](hardening.md#abuse-controls) |
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
| `KEYS_ENCRYPTION_KEY` / `KEYS_ENCRYPTION_KEY_FILE` | No | _(empty)_ | Base64 32-byte key (or a file holding it) that encrypts the stored signing key. See [Signing-key encryption](hardening.md#signing-key-encryption) |
| `KEYS_RETIREMENT_GRACE` | No | `4h` | How long a retired signing key stays in JWKS and keeps verifying |
| `KEYS_RELOAD_INTERVAL` | No | `30s` | How often `serve` re-reads signing keys from the state store |
| `KEYS_PUBLISH_DELAY` | No | `5m` | How long a new signing key is published before it signs; must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`. See the [rotation runbook](operations.md#rotation-runbook) |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_REQUESTS` | No | `true` | One access-log line per HTTP request (no query strings, headers or bodies) |
| `OTEL_TRACES_EXPORTER` | No | _(unset: off)_ | `otlp` exports OpenTelemetry traces; the other standard `OTEL_*` variables configure the exporter. See [Tracing](#tracing) |
| `TEMPOGATE_ISSUER` | No | _(empty)_ | **Client-side**, read by `tempogate login` (not the server). Equivalent to `--issuer` |
| `TEMPOGATE_LOGIN_MODE` | No | _(empty)_ | **Client-side**. `device` makes `tempogate login` use the device flow, as `--device` does; an explicit `--device` or `--device=false` wins |

## Environment variables

### Logging

| Variable | Default | Notes |
| --- | --- | --- |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error`. |
| `LOG_REQUESTS` | `true` | One structured access-log line per HTTP request on both listeners; see [Request logs](operations.md#request-logs). `false` turns it off, e.g. when an ingress or mesh already logs every request. |

### Tracing

tempogate exports OpenTelemetry traces over OTLP when you ask it to; see [Tracing](operations.md#tracing) for what a trace contains.
It reads the standard OpenTelemetry environment variables, from the environment only (not from a config file).
With the Helm chart, set them through `extraEnv`.

| Variable | Default | Notes |
| --- | --- | --- |
| `OTEL_TRACES_EXPORTER` | _(unset)_ | `otlp` turns tracing on. Unset or `none` leaves it off, and tempogate then builds no exporter and adds no per-request work. Unlike the OpenTelemetry default (`otlp`), tracing is off until you set it. Any other value, or a list, refuses to start. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` | `http://localhost:4318` | The collector. An `http://` endpoint sends in clear; use `https://` across a network you do not trust. |
| `OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_EXPORTER_OTLP_TRACES_PROTOCOL` | `http/protobuf` | `http/protobuf` or `grpc` (the gRPC default endpoint is `localhost:4317`). `http/json` is not supported. |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TIMEOUT`, `OTEL_EXPORTER_OTLP_COMPRESSION`, `OTEL_EXPORTER_OTLP_CERTIFICATE`, ... | per the specification | The rest of the exporter's settings, and their `_TRACES_` forms, as the OpenTelemetry specification defines them. |
| `OTEL_SERVICE_NAME`, `OTEL_RESOURCE_ATTRIBUTES` | `tempogate` | Resource attributes on every span. `service.version` is the running build. |
| `OTEL_TRACES_SAMPLER`, `OTEL_TRACES_SAMPLER_ARG` | `parentbased_always_on` | Which traces to keep. Each request starts its own trace, so a `parentbased_*` sampler acts as its root sampler; `traceidratio` with an argument of `0.1` keeps one trace in ten. |
| `OTEL_BSP_SCHEDULE_DELAY`, `OTEL_BSP_MAX_QUEUE_SIZE`, `OTEL_BSP_MAX_EXPORT_BATCH_SIZE`, `OTEL_BSP_EXPORT_TIMEOUT` | `5000`, `2048`, `512`, `30000` | Batching. Spans leave in batches off the request path; a full queue drops spans, never requests. |
| `OTEL_SDK_DISABLED` | `false` | `true` turns tracing off whatever else is set. |

### HTTP listener

| Variable | Default | Notes |
| --- | --- | --- |
| `HTTP_LISTENER` | `127.0.0.1:8000` | `host:port` for the single public listener (OIDC/OAuth2 + `/healthz` + `/readyz`). The loopback default is not reachable through a container or Service; set `0.0.0.0:8000` in a cluster. |
| `HTTP_TRUSTED_PROXIES` | _(empty)_ | Comma-separated CIDRs or addresses of reverse proxies in front of tempogate. tempogate takes the client address from `X-Forwarded-For` only for a connection from one of these. See [Abuse controls](hardening.md#abuse-controls). |
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

### API documentation

| Variable | Default | Notes |
| --- | --- | --- |
| `API_DOCS_ENABLED` | `false` | Dev only. Serves the OpenAPI document (`/openapi.json`, `/openapi.yaml`), the docs page (`/docs`) and the JSON schemas (`/schemas/*`) on the public listener, under the OIDC base path. `serve` refuses to start with it on unless `OIDC_ISSUER` is plain `http://`, so an https deployment cannot enable it. The admin listener never serves them. When off, they return `404`, and response bodies have no `$schema` link. In all other cases, use `tempogate gen-oas` (public spec) and `tempogate gen-oas --admin` (admin spec), which always work. |

### Admin API

The admin API has its own listener, never the public one.
It serves `/admin/keys` for integration keys, `/admin/signing-keys` for [signing-key retirement](operations.md#revocation-and-signing-key-retirement), `/admin/sessions` for [refresh-token sessions](operations.md#refresh-token-sessions), and the `/admin/healthz` liveness probe.
Every `/admin/*` route except `/admin/healthz` requires `Authorization: Bearer <admin token>`.
The same listener serves Prometheus [`GET /metrics`](operations.md#metrics), outside `/admin/*` and with no token.
You configure only the SHA-256 digest of the token, so the token itself is never in env, YAML or a ConfigMap.

| Variable | Default | Notes |
| --- | --- | --- |
| `ADMIN_LISTENER` | `127.0.0.1:8081` | `host:port` for the admin listener. Keep it on loopback unless you must manage keys from another host; a non-loopback bind also needs `ADMIN_ALLOWED_HOSTS`. |
| `ADMIN_TOKEN_SHA256` | _(empty)_ | Comma-separated lowercase-hex SHA-256 digests of the accepted admin tokens. During a rotation, list two, then remove the old one. **Empty locks the admin API:** every route except `/admin/healthz` answers 401, and tempogate logs a startup warning. A malformed entry stops `serve` at boot. |
| `ADMIN_ALLOWED_HOSTS` | `127.0.0.1:<port>,localhost:<port>,[::1]:<port>` | Comma-separated `host[:port]` values accepted in the `Host` header; an entry without a port matches any port. Other hosts get **421 Misdirected Request** before the token check, which defeats DNS rebinding from a browser. The default takes `<port>` from `ADMIN_LISTENER` and names only loopback, even for a `0.0.0.0` bind: **set it to the names your callers use** (e.g. `tempogate-admin.tempogate.svc:8081`). |
| `ADMIN_ALLOW_SYSTEM_GRANTS` | `false` | Allow keys for the `temporal-system` namespace. Temporal treats a `temporal-system` role as cluster-wide, so these grants answer 403 unless this is `true`. Enable it only while you mint the keys that need it. |
| `ADMIN_KEYS_MAX_TTL` | `2160h` (90 days) | Go duration; the latest `expires_at` that an integration key can have. `expires_at` is required, and a value in the past or beyond this cap answers 400. Temporal ignores revocation, so this cap limits how long a leaked key works there, unless you [retire its signing key](operations.md#revocation-and-signing-key-retirement). Must be positive. |

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
| `KEYS_RETIREMENT_GRACE` | `4h` | Go duration; how long a retired signing key stays in `/.well-known/jwks.json` and keeps verifying. After it, no token signed by that key verifies, whatever its `exp` ([details](operations.md#revocation-and-signing-key-retirement)). The default equals the 4 h access-token TTL, so tokens minted just before a retirement live out their natural life. `0` unpublishes a key at retirement. Must not be negative. |
| `KEYS_RELOAD_INTERVAL` | `30s` | Go duration; how often `serve` re-reads signing keys from the state store, so `tempogate keys generate --force` and `tempogate keys retire` from another process apply with no restart. A retire through the admin API applies at once. Must be positive. |
| `KEYS_PUBLISH_DELAY` | `5m` | Go duration; how long a new signing key is in `/.well-known/jwks.json` before it signs. Until then the previous non-retired key signs; with no other non-retired key (fresh install, or every key retired) the new key signs at once. **Must exceed Temporal's JWKS refresh interval plus `KEYS_RELOAD_INTERVAL`** ([why](operations.md#why-new-keys-wait-before-signing)). `0` signs as soon as `serve` loads the key. Must not be negative. |

### State store

| Variable | Default | Notes |
| --- | --- | --- |
| `STATE_DRIVER` | `sqlite` | `sqlite` (one replica, a file on a volume) or `postgres` (one or more replicas on a shared PostgreSQL database). Every subcommand that opens the store (`serve`, `migrate`, `keys`, `sessions`) uses this setting; `state copy` reads `STATE_SQLITE_PATH` and writes to `STATE_POSTGRES_*` whatever it says. |
| `STATE_REAPER_INTERVAL` | `5m` | Go duration; how often `serve` deletes expired state (see below). `0` disables the reaper. |

Both backends hold the same data with the same guarantees (the contract in `state/doc.go`, checked against both by the `state/storetest` suite), and `tempogate migrate` creates or upgrades either schema.
`tempogate state copy` moves an installation from SQLite to PostgreSQL ([runbook](operations.md#switching-from-sqlite-to-postgresql)).

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
- The Helm chart runs this mode with `state.driver=postgres`; see [HA mode on PostgreSQL](../charts/tempogate/README.md#ha-mode-on-postgresql).

### OIDC — server identity and Google federation

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `OIDC_ISSUER` | for real deploys | `http://127.0.0.1:8000` | Externally reachable base URL; advertised as `issuer`, and the base of `jwks_uri`. Can include a path ([sub-path hosting](#sub-path-hosting)). **Must be `https://`** unless the host is loopback (`localhost`, `127.0.0.0/8`, `::1`), or `tempogate serve` refuses to start. |
| `OIDC_ALLOW_INSECURE_ISSUER` | no | `false` | **Development only.** Lets `serve` start, with a warning, on a plain-http `OIDC_ISSUER` with a non-loopback host (e.g. the docker-compose demo's `http://tempogate:8000`). Over plain http, anyone on the path can substitute the discovery document and signing keys. `migrate`, `keys` and `version` never check the issuer. |
| `OIDC_CLIENTS` | for any login | _(empty)_ | Comma-separated `id:redirect_uri`; the first `:` splits the id from the URI. Each value is an **exact** redirect URI, never a prefix ([Redirect URI registration](#redirect-uri-registration)). Repeat an id for several URIs; an empty value (`tempogate-device:`) registers a device-only client. **Every client here is public, and PKCE is mandatory.** Register the loopback CLI as `tempogate-cli:http://127.0.0.1/callback`. The [device flow](cli-device-login.md) also needs `tempogate-device:` and `tempogate-device-ui:<issuer>/device/sso-callback`, and `serve` refuses to start without the latter. Invalid entries stop the server at startup. |
| `OIDC_ALLOW_INSECURE_REDIRECT_URIS` | no | `false` | Dev only. Allows plain-`http` non-loopback redirect URIs in `OIDC_CLIENTS` (e.g. `http://temporal-ui:8080/auth/sso/callback` in a local Docker Compose stack). Keep it off in production: anyone on the network can read a code sent over plain http. |
| `OIDC_CLIENT_SECRETS` | no | _(empty)_ | Comma-separated `id:secret`. A separate, auditable opt-in that makes a registered client **confidential** (the [PKCE carve-out](pkce-and-confidential-clients.md)): the Temporal Web UI, which does not implement PKCE, and `tempogate-device-ui`, tempogate's own client for the device verification page's Google SSO. An entry for an unregistered id fails fast. |
| `OIDC_ALLOWED_DOMAINS` | for any login | _(empty)_ | Comma-separated email domains, exact match, checked on Google's verified email at sign-in and on every [refresh](operations.md#refresh-token-sessions). **Empty admits nobody.** |
| `OIDC_ALLOWED_HOSTED_DOMAINS` | recommended | _(empty)_ | Comma-separated Google Workspace domains. When set, Google's `id_token` must have an `hd` claim in this list (exact, case-insensitive). See [Hosted domain (Workspace mode)](authorization.md#hosted-domain-workspace-mode). |
| `OIDC_AUTHZ_RULES_<n>` | this or the next | _(none)_ | Indexed list (`OIDC_AUTHZ_RULES_0`, `OIDC_AUTHZ_RULES_1`, ...; YAML `oidc.authz.rules`) of rules `"<selector>=<namespace>:<role>[,...]"` that set the Temporal permissions of a person's access token. See [Authorization](authorization.md#authorization). |
| `OIDC_AUTHZ_DEFAULT_PERMISSIONS` | this or the previous | _(empty)_ | Comma-separated permissions for admitted people that no rule matches; empty denies them. **`serve` refuses to start when this and the rules are both empty.** See [Upgrading to deny-by-default authorization](upgrading.md#upgrading-to-deny-by-default-authorization). |
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

## See also

- [Helm chart values](../charts/tempogate/README.md#values) - the same settings as chart `values.yaml` keys, plus Secret wiring.
- [docs/getting-started.md](getting-started.md) - these settings in a working end-to-end context.
