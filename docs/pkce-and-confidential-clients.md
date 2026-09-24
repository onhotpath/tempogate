# PKCE posture and the confidential-client carve-out

This document explains, for anyone auditing tempogate's authorization-code
flow, **why PKCE is mandatory by default**, **why a single narrow exception
exists**, and **why that exception is safe**. It also covers two related
OpenID Connect conformance behaviours (`nonce` and `aud`) that the same flow
implements.

## TL;DR

* Default and strict path: **PKCE (RFC 7636, S256 only) is required** for
  every client. This matches the OAuth 2.0 Security BCP (RFC 9700) and
  OAuth 2.1.
* One carve-out: a client **registered with a secret** (a *confidential*
  client) may complete the flow **without PKCE**, but only by
  **authenticating that secret at the token endpoint**. PKCE is still
  enforced for such a client if it *does* send a `code_challenge`.
* A client with **no secret** (a *public* client) can **never** skip PKCE.
  The carve-out can never collapse into "no PKCE *and* no client
  authentication".
* The carve-out exists for one concrete, widespread class of relying party:
  an OIDC client that authenticates with a shared client secret and does not
  implement PKCE. The self-hosted [Temporal Web UI](https://github.com/temporalio/ui-server)
  is the motivating example.
* Independently of PKCE, the flow now also honours OIDC Core's `nonce`
  round-trip and stamps the ID token's `aud` with the requesting
  `client_id`. These are pure spec-conformance fixes with no security
  downside.

## The RFC landscape

PKCE — Proof Key for Code Exchange — defends against **authorization-code
interception**. The client generates a random `code_verifier`, sends
`code_challenge = BASE64URL(SHA256(code_verifier))` at `/authorize`, and
presents the raw `code_verifier` at `/token`; the server checks they match.
An attacker who intercepts the `code` (redirect hijack, logs, referrer
leakage, a malicious app claiming a redirect URI) still cannot redeem it.

Whether PKCE is *required* depends on which document you read:

| Spec | PKCE status |
| --- | --- |
| OAuth 2.0 — RFC 6749 (2012) | Did not exist. |
| RFC 7636 (2015) | RECOMMENDED for public clients. |
| OAuth 2.0 Security BCP — RFC 9700 (2025) | REQUIRED for the auth-code flow, all client types. |
| OAuth 2.1 (draft) | PKCE mandatory. |
| OpenID Connect Core 1.0 | Does not mandate PKCE; relies on `nonce` for a *different* attack (ID-token injection/replay). |

tempogate's default — PKCE mandatory, `S256` only, `plain` rejected — is the
RFC 9700 / OAuth 2.1 posture. It is deliberately stricter than RFC 6749. The
default is not relaxed.

## The interoperability problem

A confidential OAuth2 client predates the "PKCE for everyone" guidance: it
authenticates to the token endpoint with a **client secret** (RFC 6749
§2.3.1, HTTP Basic or form body) and never implements PKCE. Code-interception
defence comes from the secret plus TLS rather than from a per-request proof.
This is a valid, pre-OAuth-2.1 model — just not BCP-current.

The Temporal Web UI's OIDC client is exactly this class (its behaviour is
public; see `temporalio/ui-server`). Concretely it:

* sends no `code_challenge` at `/authorize` and no `code_verifier` at
  `/token` (PKCE is not implemented and cannot be configured on);
* authenticates with a configured client secret;
* sends a `nonce` at `/authorize` and **rejects** any ID token whose `nonce`
  claim does not match;
* verifies the ID token with its `client_id` as the expected audience, so
  the token's `aud` **must** contain that `client_id`.

A PKCE-only authorization server cannot complete a login with such a client
at all — the flow dies at `/authorize`. Being "more correct" than a client
that cannot interoperate is still a broken product. Mature authorization
servers (e.g. Keycloak, Auth0) resolve this with a **per-client policy**:
PKCE enforced if presented, required for public clients, optional for a
confidential client that authenticates with its secret.

## The carve-out, precisely

The relaxation is intentionally minimal and gated on a single fact: **does
the client have a registered secret?**

* **`/authorize`** — if `code_challenge` is absent, the request is rejected
  unless the client is confidential (`IsConfidential`). If a challenge *is*
  present, `S256` is still required regardless of client type. The carve-out
  only ever *widens* behaviour when a challenge is absent; it never weakens
  validation of a challenge that was sent.
* **`/token`** — the redeemed authorization code itself decides which proof
  is required:
  * a code minted **with** a PKCE challenge always demands a valid
    `code_verifier` (unchanged, strict — and it still applies to a
    confidential client that opted into PKCE);
  * a code minted **without** a challenge (only reachable via the
    confidential path at `/authorize`) requires the client to authenticate
    its secret, compared in constant time. A public client has no secret, so
    this fails closed for it — a public client can never ride the carve-out
    even if it presents a code with no challenge.
* A request proving **neither** a PKCE verifier **nor** a client secret is
  rejected as `invalid_request` *before* the single-use code is consumed, so
  a malformed/confused request cannot burn a code or downgrade the strict
  default.

Net properties:

* Public clients: PKCE mandatory, exactly as before. No change, no
  relaxation.
* Confidential clients: may omit PKCE, but must then authenticate with their
  secret; if they use PKCE, it is fully enforced.
* There is no configuration in which a flow completes with neither PKCE nor
  client authentication.

## Configuration

The carve-out is an explicit, auditable opt-in kept **separate** from the
primary client allowlist:

* `OIDC_CLIENTS` — comma-separated `id:redirect_uri_prefix`. Every client
  declared here is **public**: PKCE mandatory.
* `OIDC_CLIENT_SECRETS` — comma-separated `id:secret`. An entry promotes an
  already-registered client to **confidential**. A secret for an
  unregistered `id`, a duplicate, or an empty value fails fast at startup,
  so the relaxation cannot be half-configured or enabled by a typo.

Keeping secrets out of `OIDC_CLIENTS` means the redirect allowlist — the
always-present, security-critical config — is unchanged, and turning the
carve-out on for a client is a visible, deliberate second step.

## Related OIDC Core conformance

Two behaviours in the same flow are pure spec-conformance, independent of the
PKCE decision and with no security downside:

* **`nonce` round-trip (OIDC Core §2).** If a relying party sends `nonce` at
  `/authorize`, the provider MUST return it in the ID token. tempogate now
  carries `nonce` from the authorization request through the authorization
  code into the minted token's `nonce` claim. It is omitted on the
  refresh-token path, where OIDC does not bind a nonce. Not echoing a
  client-supplied nonce is a spec violation that breaks *any* conformant OIDC
  client, not just one.
* **`aud` = requesting `client_id` (OIDC Core).** An ID token's `aud` must
  contain the client it was issued to. tempogate stamps the requesting
  `client_id` as the audience. Temporal's frontend authorizer does not
  enforce `aud`, so this is additive for the gRPC path while making the ID
  token valid for OIDC clients that verify it.

## Security analysis

The threat PKCE addresses for *public* clients is authorization-code
interception by a party that can receive the redirect but does not hold a
client secret. A confidential client that authenticates its secret at the
token endpoint already forces an attacker to possess that secret to redeem an
intercepted code; the secret plus TLS covers the same threat class that PKCE
covers for secret-less clients. The residual gap versus OAuth 2.1 is that
PKCE additionally binds the code to a *single authorization request*, which a
static secret does not. tempogate accepts that bounded, well-understood
trade-off **only** for explicitly-registered confidential clients, **only**
when they do not send a challenge, and **never** for public clients — and
keeps PKCE fully enforced everywhere else. This is the minimum relaxation
that lets a stock confidential OIDC relying party interoperate while keeping
the default strict and BCP-aligned.
