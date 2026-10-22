# Architecture

## The gap tempogate fills

Self-hosted Temporal ships two extension points and uses neither by itself:

- the **Web UI** consumes any OIDC issuer via `TEMPORAL_AUTH_*` env vars;
- the **gRPC frontend** verifies JWTs against a configurable JWKS endpoint and
  reads a `permissions: ["<namespace>:<action>", ...]` claim.

Together these cover browser SSO and machine auth — but only if something
issues the tokens. tempogate is that something. It is an OIDC provider to
Temporal and an OAuth2 client of Google.

## How it fits together

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

1. The Web UI redirects the browser to tempogate `/authorize`.
2. tempogate federates the sign-in to Google (the authorization-code flow,
   server-side, with tempogate's own PKCE and nonce, and the internal
   `state` bound to the browser by a short-lived cookie), then applies its
   email-domain gate to Google's verified email. See
   [Google leg](configuration.md#google-leg).
   Google sits behind an upstream connector interface: the server owns the
   state, the browser binding, the admission gates and the tokens, and a
   connector owns only its upstream protocol, so another identity provider
   can be added without touching the callback.
3. tempogate mints two JWTs and completes the OIDC flow back to the UI:
   a short-lived access token (`aud` = the Temporal audience, a
   `permissions` claim) and a separate ID token for the UI's login (`aud` =
   the calling client, OIDC `nonce` round-tripped, no permissions).
4. The browser calls the Temporal gRPC frontend with the access token. The
   frontend's **stock** default authorizer fetches tempogate's
   `/.well-known/jwks.json`, verifies the signature, and reads the
   `permissions` claim. No Temporal-side custom code. The ID token grants
   nothing there. See [Access tokens and ID tokens](configuration.md#access-tokens-and-id-tokens).

`tempogate login` runs the same OIDC flow from a laptop over an ephemeral
`127.0.0.1` loopback port, giving users and unattended machines the same
tokens without a kept-open browser
([docs/cli-loopback-login.md](cli-loopback-login.md)).

## Why not a sidecar proxy or a fork?

| Approach | Pros | Cons |
| --- | --- | --- |
| **tempogate (OIDC + OAuth2 AS)** | Stateless integration with stock Temporal. No fork, no proxy. | A second component to operate. |
| Sidecar reverse-proxy in front of UI/gRPC | Auth logic outside Temporal. | Has to demux gRPC + HTTP; brittle around streaming; obscures Temporal's own auth machinery. |
| Forked `temporal-server` | Total control. | Permanent rebase tax; loses upstream support; defeats the "self-hosted but supported" posture. |

tempogate fills exactly the gap Temporal's own documentation already
describes — point the Web UI at the issuer and the frontend's
`jwtKeyProvider.keySourceURIs` at the JWKS — rather than wrapping or rebuilding
Temporal.

## Design decisions

**Single binary, subcommands.** One distroless binary with `serve`, `login`,
`token`, `keys`, `sessions`, `migrate`, `version`. Operators run `serve`; the
same binary is the laptop CLI. Migrations are embedded and applied by `migrate`.
Each server subcommand builds only the dependencies it uses, when it runs:
`serve` (and `gen-oas`) need the full OIDC configuration, while `migrate`,
`keys` and `sessions` need just the state store (`STATE_DRIVER` and its settings, plus
`KEYS_ENCRYPTION_KEY` for `keys` when signing keys are encrypted) and
`version` nothing.

**Pluggable state, SQLite by default.** The state store (signing keypair,
authorization codes, refresh tokens) is an interface with two backends,
chosen by `STATE_DRIVER`. The default is SQLite on a PersistentVolumeClaim via
the pure-Go `modernc.org/sqlite` driver: no CGO, no external database to run
a small deployment. SQLite tolerates one writer, so with it the deployment is
single-replica; the chart enforces this (`replicaCount: 1`, autoscaling off,
`Recreate` strategy). PostgreSQL 15+ (`state/postgres`, the native `pgx`
driver) is the shared backend for several replicas: where SQLite relies on
its single writer, it takes row locks under READ COMMITTED (a per-family row
that a rotation locks FOR SHARE and a revocation updates first, the device
code row on poll, the active keypairs on retirement), runs migrations and
first-boot key generation under transaction-level advisory locks, reaps in
`FOR UPDATE SKIP LOCKED` batches on every replica, and tells every replica of
key changes and integration-key revocations through `LISTEN/NOTIFY`, with the
periodic reloads kept as the backstop. Each backend has its own migrations
directory, paired by number and name from the Postgres baseline (SQLite's
0014) on. What any backend must guarantee (consume-once, conditional
transitions, ordering, an application-owned clock, optional change
notifications) is written down in `state/doc.go` and checked by the
`state/storetest` conformance suite, which CI runs against SQLite and against
PostgreSQL 15 and 18.

**Nothing in the state store is a usable credential on its own.** A copy of
the database is the realistic leak (a backup, a volume snapshot, another
local user), so the files are owner-only and the bearer secrets in them
(refresh tokens, authorization and device codes, verification-page session
ids) are stored as their SHA-256 and looked up by it. The signing key is the
one secret that must be recoverable; an optional key-encryption key
(`KEYS_ENCRYPTION_KEY`, kept outside the database) stores it AES-256-GCM
encrypted, so the database alone cannot mint tokens.

**Refresh tokens are a revocable session, not a bearer forever.** Each
sign-in starts a refresh-token family: single-use tokens that rotate on every
exchange and carry the original sign-in time (`auth_time`) and a family id.
A refresh is refused once the session is idle for `OIDC_REFRESH_TOKEN_TTL` or
older than `OIDC_REFRESH_MAX_LIFETIME` from sign-in, or when the email's
domain has left `OIDC_ALLOWED_DOMAINS` (which also revokes the family).
Rotated tokens are kept as tombstones rather than deleted, so presenting one
again is recognised as reuse and revokes the whole family (RFC 9700
§4.14.2). Operators revoke by email, Google subject or family with
`tempogate sessions revoke` or its admin-API twin, `POST
/admin/sessions/revoke`. The jti denylist used for integration keys plays no part here: it
covers JWTs, and refresh tokens are opaque rows.

**Bounded anonymous input.** The OIDC endpoints are reachable without credentials and some write a row per request.
So request parameters have length caps, the endpoints that write state or check credentials are rate-limited per client address (trusting `X-Forwarded-For` only from configured proxies), and `serve` runs a reaper that deletes expired rows.
A flood can neither fill the state volume nor outlive its expiry.
Refresh tokens are reaped a whole family at a time, once no token in it can be used, so the tombstones reuse detection relies on are never removed early.
See [docs/configuration.md](configuration.md#abuse-controls).

**Migration is a separate step.** `serve` refuses to run against a stale
schema. In Kubernetes `migrate` runs as an initContainer of the single
tempogate pod; the `Recreate` strategy stops the previous pod first, so the
migration never races a running server for the SQLite file or its
ReadWriteOnce volume. With Postgres, migrations take an advisory lock and
apply every pending file in one transaction, so concurrent runs are safe and
a failed one leaves no partial schema; they must be expand/contract, because
a rolling update runs two versions against one database.

**PKCE mandatory, with one auditable carve-out.** Every registered client is
public and must use PKCE. A deliberately separate `OIDC_CLIENT_SECRETS`
setting promotes specific clients to confidential for the narrow case of a
client that cannot do PKCE (the Temporal Web UI).
A confidential client always authenticates its secret at `/token`, and PKCE
is enforced on top whenever it sends a challenge.
Keeping the relaxation in
its own setting makes it explicit and reviewable; an entry for an unregistered
client fails fast. See
[docs/pkce-and-confidential-clients.md](pkce-and-confidential-clients.md).

**Authorization is configuration, deny by default.** Admission (Google
sign-in, `OIDC_ALLOWED_DOMAINS`, Workspace mode) says who may sign in; the
server-only `authz` package says what their access token may do, from static
`email:`/`domain:` rules (`OIDC_AUTHZ_RULES_<n>`) and an optional default.
`oidc` sees it only as a consumer-side `PermissionResolver`, bound with
`fx.As` in the server modules, so the lean CLI never links it. `Token.issue`
resolves permissions for every grant (code, refresh, device) and puts them in
the access token only; the Google callback and the device verification page
ask too, so a person with no grant gets `access_denied` before any code or
token exists. Refresh resolves again after the domain re-check, so a rule
change reaches a session at its next refresh and an empty result revokes the
family. Resolution is in-memory and needs nothing from Google, because
tempogate keeps no upstream refresh token. `serve` refuses to start with no
rules and no default. Integration keys keep their own single (namespace,
role). See [docs/configuration.md](configuration.md#authorization).

**Authenticated admin API.** Integration keys are minted and revoked, signing
keys retired and refresh-token sessions listed and revoked on a separate admin
listener whose routes require a bearer admin token (configured only as its
SHA-256), reject unexpected `Host` headers to defeat DNS rebinding, refuse
cluster-wide `temporal-system` grants unless explicitly allowed, and log every
mint and revoke. See [docs/configuration.md](configuration.md#admin-api).

**Revocation is honest about Temporal.** Temporal verifies a token against
the JWKS and its `exp`, never against tempogate's state, so the `jti`
denylist behind `DELETE /admin/keys/{id}` only protects tempogate's own
endpoints. Integration keys therefore must expire (`ADMIN_KEYS_MAX_TTL`,
90 days by default), and the hard kill switch is retiring a signing key:
after `KEYS_RETIREMENT_GRACE` its `kid` leaves the JWKS and every token it
signed stops verifying everywhere. `serve` re-reads keys every
`KEYS_RELOAD_INTERVAL`, so rotation and retirement need no restart. A new
key is published at once but signs only after `KEYS_PUBLISH_DELAY`, because
Temporal never refetches JWKS on an unknown `kid`. See
[docs/configuration.md](configuration.md#revocation-and-signing-key-retirement).

**Observable without leaking.** Prometheus metrics (logins, tokens by grant,
OAuth2 error codes, Google latency, state-store errors) are served on the
private admin listener only, never the public one. Feature packages report
through small observer interfaces of their own, so only the server build
links the Prometheus client; the lean CLI does not. Every request is logged
as one structured line from an allowlist of fields (path without query, no
headers or bodies), and `/readyz` checks the state store on every call while
`/healthz` stays a pure liveness probe. See
[docs/configuration.md](configuration.md#observability).

**Co-hostable.** `OIDC_ISSUER` may carry a path, so the whole OIDC surface
can serve under a prefix on a shared hostname while health probes stay at the
root. See [docs/configuration.md](configuration.md#sub-path-hosting).

**Server errors stay server-side.** Every response carries an `X-Request-Id` header.
A 5xx body is generic (for example `internal server error (request id <id>)`) and never includes the underlying error; the device verification page shows the same id on its HTML error page.
The real cause is logged at `error` level with a matching `request_id` field, so a user's report can be traced with `kubectl logs | grep <id>`.
4xx bodies, including OAuth `error` / `error_description`, are unchanged, and so is the one deliberate OAuth-shaped 5xx: `502 upstream_error` from `/callback/google`, whose description is fixed text.

## See also

- [docs/getting-started.md](getting-started.md) — the architecture running end
  to end in ten minutes
- [docs/configuration.md](configuration.md) — every setting
- [charts/tempogate/README.md](../charts/tempogate/README.md) — the
  Kubernetes deployment shape and its constraints
