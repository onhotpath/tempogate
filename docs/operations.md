# Operations

How to run tempogate day to day: manage sessions, revoke access, rotate signing keys, move to PostgreSQL, and watch the server.
For the settings, see the [configuration reference](configuration.md).

## Refresh-token sessions

Each sign-in starts a session: a family of single-use refresh tokens that rotate on every exchange.
tempogate refuses a refresh with `invalid_grant` when:

- the session is idle for longer than `OIDC_REFRESH_TOKEN_TTL`, or older than `OIDC_REFRESH_MAX_LIFETIME`;
- the session is revoked;
- the email domain is no longer in `OIDC_ALLOWED_DOMAINS` (logs `refresh_domain_not_allowed`);
- the [authorization rules](authorization.md#authorization) no longer grant the person anything (logs `refresh_authz_denied`);
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
The [admin API](configuration.md#admin-api) offers the same operations over HTTP, with no exec into the pod:

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

## Switching from SQLite to PostgreSQL

`tempogate state copy` copies a SQLite state store into PostgreSQL, so you can move to [`STATE_DRIVER=postgres`](configuration.md#postgresql) and run several replicas without rotating signing keys, minting integration keys again or signing anyone out.
It copies every table: signing keys, integration keys and their revocations, refresh-token sessions, and pending sign-ins and device codes.

1. **Stop tempogate** (scale to 0), so nothing writes to the SQLite file during or after the copy: such a write would be lost.
2. **Copy**, with the new release's binary, from somewhere that can read the SQLite file and reach the database, e.g. a one-off pod that mounts the state volume:

   ```bash
   STATE_SQLITE_PATH=/var/lib/tempogate/state.db \
   STATE_POSTGRES_DSN='postgres://tempogate@db.example.com:5432/tempogate?sslmode=verify-full&require_auth=scram-sha-256' \
   tempogate state copy
   ```

   `--from <path>` overrides `STATE_SQLITE_PATH`, and the target takes the same `STATE_POSTGRES_*` settings, TLS policy included, as `serve`.
   The source must be migrated by this release (if it is not, run `tempogate migrate` against it with `STATE_DRIVER=sqlite`); the copy migrates the target itself.
   It runs in one transaction and prints the rows copied per table, so it writes everything or nothing.
3. **Start tempogate** with `STATE_DRIVER=postgres` and the same `STATE_POSTGRES_*` settings.
   Keep the SQLite file until you are satisfied: switching back to it loses only what happened after the copy.

The copy refuses a database that already holds state (a `serve` that booted against it has generated a signing key, for example).
`--force` replaces that state instead, deleting it in the same transaction.
Both stores must be at the same schema version, and the copy refuses any table or column that exists on only one side rather than drop it.

### With the Helm chart

With `state.driver=postgres` the chart no longer renders the state PVC, so the upgrade that switches drivers deletes a chart-managed claim, and with it the SQLite file under the usual `Delete` reclaim policy.
Keep it first, then copy from a one-off pod that mounts it:

1. Keep the claim and stop tempogate in one upgrade:

   ```bash
   helm upgrade tempogate oci://ghcr.io/onhotpath/charts/tempogate --reuse-values \
     --set replicaCount=0 \
     --set-string 'persistence.annotations.helm\.sh/resource-policy=keep'
   ```

2. Copy, with the PVC (`<fullname>-state`, so `tempogate-state` for a release named `tempogate`, or your `persistence.existingClaim`) and the DSN Secret the chart will use; mount the CA bundle too if the DSN names `sslrootcert`:

   ```yaml
   apiVersion: v1
   kind: Pod
   metadata:
     name: tempogate-state-copy
   spec:
     restartPolicy: Never
     securityContext: { runAsNonRoot: true, runAsUser: 65532, runAsGroup: 65532, fsGroup: 65532 }
     containers:
       - name: copy
         image: ghcr.io/onhotpath/tempogate:<new release>
         args: ["state", "copy", "--from", "/var/lib/tempogate/state.db"]
         env:
           - name: STATE_POSTGRES_DSN_FILE
             value: /etc/tempogate/postgres/dsn
         volumeMounts:
           - { name: state, mountPath: /var/lib/tempogate }
           - { name: dsn, mountPath: /etc/tempogate/postgres, readOnly: true }
     volumes:
       - name: state
         persistentVolumeClaim: { claimName: tempogate-state }
       - name: dsn
         secret: { secretName: tempogate-postgres, items: [{ key: dsn, path: dsn }] }
   ```

   `kubectl logs tempogate-state-copy` shows the rows copied per table; delete the pod once it has completed.
3. Switch: `helm upgrade` with `state.driver=postgres`, `state.postgres.dsnSecretRef` and the replica count you want ([chart README](../charts/tempogate/README.md#ha-mode-on-postgresql)).
   The PVC stays behind, now outside the release; delete it with `kubectl delete pvc` once you no longer need to switch back.

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
| `tempogate_logins_total` | counter | `result` (`success`, `failure`), `reason` | Completed Google sign-in callbacks. `reason` is `none` on success, else one of `missing_state`, `state_not_bound` (the callback came from another browser than the one that started the sign-in), `unknown_state`, `expired_request`, `connector_mismatch` (the sign-in was started for another connector), `upstream_denied`, `missing_code`, `upstream_error`, `email_unverified`, `domain_not_allowed`, `hosted_domain_not_allowed` (the `hd` claim failed [Workspace mode](authorization.md#hosted-domain-workspace-mode)), `authz_denied` (admitted, but no [authorization rule](authorization.md#authorization) grants anything; sent back as `access_denied`), `internal`. |
| `tempogate_tokens_issued_total` | counter | `grant` (`authorization_code`, `refresh_token`, `device_code`) | Tokens minted by `/token`. |
| `tempogate_token_errors_total` | counter | `grant` (as above, or `other`), `error` | Failed `/token` requests by OAuth2 error code (`invalid_request`, `invalid_grant`, `invalid_client`, `unauthorized_client`, `unsupported_grant_type`, `authorization_pending`, `slow_down`, `access_denied`, `expired_token`) or `server_error` for a 500. `invalid_client` is a confidential client that failed to authenticate. Device-flow polling counts `authorization_pending` on every poll. Requests the rate limiter rejects never reach `/token` and are counted in `tempogate_rate_limited_total` instead. |
| `tempogate_authz_denied_total` | counter | `stage` (`login`, `device_verification`, `authorization_code`, `refresh_token`, `device_code`) | Admitted people refused because no [authorization rule](authorization.md#authorization) grants them anything: at the Google callback, on the device verification page, or at `/token` for the grant named (a rule removed after sign-in). The `login` refusals are also in `tempogate_logins_total{reason="authz_denied"}` and the `refresh_token` ones in `tempogate_refresh_family_revocations_total{event="refresh_authz_denied"}`. |
| `tempogate_refresh_family_revocations_total` | counter | `event` (`auth_code_reuse`, `refresh_token_reuse`, `refresh_domain_not_allowed`, `refresh_authz_denied`, `refresh_connector_removed`) | Refresh-token families tempogate revoked on its own: a replayed authorization code or refresh token, a refresh for an email domain no longer in `OIDC_ALLOWED_DOMAINS`, one the authorization rules no longer grant anything, or one whose sign-in connector is no longer configured. The refused request is also counted as `invalid_grant`. Operator revocations (`tempogate sessions revoke`, `POST /admin/sessions/revoke`) are not counted; the admin API's [audit log](configuration.md#admin-api) records the latter. |
| `tempogate_rate_limited_total` | counter | `endpoint` (`authorize`, `device_authorization`, `device_verification`, `token`) | Requests answered `429` by the per-client [rate limits](hardening.md#abuse-controls). The client address is never a label. |
| `tempogate_upstream_request_duration_seconds` | histogram | `op` (`discovery`, `code_exchange`, `verify_id_token`) | Latency of calls to Google, failed calls included. `verify_id_token` includes the JWKS fetch on a key-cache miss. `discovery` runs on first use and again on each retry after a failure; a failure served from inside the retry backoff is not a call and is not counted. |
| `tempogate_upstream_errors_total` | counter | `op`, `reason` (`timeout`, `error`) | Failed calls to Google. `timeout` is a call that got no answer within the [upstream timeout](configuration.md#google-leg); `error` is any other failure, including an error answer from Google. |
| `tempogate_db_errors_total` | counter | `op` (the store operation, e.g. `consume_refresh`, `probe`, `reap`) | State-store operations that failed. A miss (unknown or replayed code or token) is not an error. |
| `tempogate_build_info` | gauge | `version`, `commit` | Always `1`; identifies the running build. |

The Go runtime (`go_*`) and process (`process_*`) collectors are also exposed.
tempogate takes every label value from a fixed set: emails, client IDs, tokens and raw request input never become labels.

### Tracing

tempogate can export OpenTelemetry traces over OTLP.
Tracing is off by default; `OTEL_TRACES_EXPORTER=otlp` turns it on, and the other standard `OTEL_*` variables point it at a collector ([settings](configuration.md#tracing)).

- **One trace per request**, on both listeners.
  Its root is the request's server span, named after the route template that matched (`POST /token`, `GET /callback/{connector}`), or the method alone when none did.
  It carries `http.request.method`, `http.route`, `http.response.status_code`, `tempogate.listener` (`public` or `admin`) and `tempogate.request_id`, which is the `X-Request-Id` the response carries and the `request_id` of its [access-log line](#request-logs).
  A `5xx` marks the span as failed, with `error.type` set to the status code and the error detail the client never sees (the one logged as `request failed`) as its status message.
- **Child spans** cover the request's own work: `upstream <op>` for each call to Google, and `store <op>` for each state-store operation.
  `<op>` is the `op` label of the matching metric (`tempogate_upstream_request_duration_seconds`, `tempogate_db_errors_total`).
  A failed one has `error.type` set to `timeout` or `error` (Google), or `db_error` (store), and records the error's message.
- **A new trace for every request.** tempogate does not join an incoming `traceparent`: the public listener faces the internet, and a caller could otherwise pick trace IDs and force sampling.
  It sends no trace context to Google either.
- **Not traced:** probes and scrapes (`/healthz`, `/readyz`, `/admin/healthz`, `/metrics`), and background work (expired-state reaping, signing-key reloads, the denylist feed).
  Background work still counts in the metrics.
- **No secrets or identities in span attributes.** The rule for metric labels applies: no emails, client IDs, tokens or raw request input.
  Spans carry route templates and operation names, never the URL path, query string, headers, client address or user agent.
- **Errors keep their text, with secrets and personal data masked.** A failed span records its error's message, because that is what makes a trace worth reading.
  The message can quote what the failing library saw, such as the client ID in a refused ID token's audience.
  tempogate masks every value it knows to be sensitive wherever it appears in that message: credentials (client secrets, codes, tokens, session ids, keys, the database password) become `[REDACTED]`, emails become `a***@example.com`, and client IDs of 8 characters or more keep a short prefix (`tempog***`).
  It can only mask values it handled itself, in the form it handled them (not URL-escaped or re-encoded); give your trace backend the access controls you give your logs.
- **Export never fails a request.** Spans leave in batches off the request path.
  If the collector is down, the batch is dropped and logged at `warn` as `opentelemetry error`.
  `serve` flushes the last batch when it stops, waiting at most 5 seconds for the collector.

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
