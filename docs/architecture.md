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
   server-side), then applies its email-domain gate to Google's verified
   email.
3. tempogate mints a short-lived JWT — `aud` = the calling client, OIDC
   `nonce` round-tripped, a `permissions` claim — and completes the OIDC
   flow back to the UI.
4. The browser calls the Temporal gRPC frontend with that JWT. The
   frontend's **stock** default authorizer fetches tempogate's
   `/.well-known/jwks.json`, verifies the signature, and reads the
   `permissions` claim. No Temporal-side custom code.

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
`token`, `keys`, `migrate`, `version`. Operators run `serve`; the same binary
is the laptop CLI. Migrations are embedded and applied by `migrate`.

**Pluggable state, SQLite by default.** The state store (signing keypair,
authorization codes, refresh tokens) is an interface; the default is SQLite on
a PersistentVolumeClaim via the pure-Go `modernc.org/sqlite` driver — no CGO,
no external database to run a small deployment. SQLite tolerates one writer,
so the deployment is single-replica until a shared backend lands; the chart
enforces this (`replicaCount: 1`, autoscaling off, `Recreate` strategy).

**Migration is a separate step.** `serve` refuses to run against a stale
schema. In Kubernetes a dedicated `migrate` Job runs alongside the release
(not a Helm hook — a hook Job mounting the chart's own first-consumer PVC
deadlocks); a `serve` pod that starts first simply exits and is restarted
until the schema is current.

**PKCE mandatory, with one auditable carve-out.** Every registered client is
public and must use PKCE. A deliberately separate `OIDC_CLIENT_SECRETS`
setting promotes specific clients to confidential for the narrow case of a
client that cannot do PKCE (the Temporal Web UI). Keeping the relaxation in
its own setting makes it explicit and reviewable; an entry for an unregistered
client fails fast. See
[docs/pkce-and-confidential-clients.md](pkce-and-confidential-clients.md).

**Flat authorization, today.** Every admitted identity receives cluster-level
access (`temporal-system:admin`) — the value Temporal's default ClaimMapper
needs for cluster APIs. Group- or role-derived per-namespace scoping, and a
revocable long-lived integration-key admin API, are planned; the JWT shape and
the `permissions` claim are already in place for them.

**Co-hostable.** `OIDC_ISSUER` may carry a path, so the whole OIDC surface
can serve under a prefix on a shared hostname while health probes stay at the
root. See [docs/configuration.md](configuration.md#sub-path-hosting).

## See also

- [docs/getting-started.md](getting-started.md) — the architecture running end
  to end in ten minutes
- [docs/configuration.md](configuration.md) — every setting
- [charts/tempogate/README.md](../charts/tempogate/README.md) — the
  Kubernetes deployment shape and its constraints
