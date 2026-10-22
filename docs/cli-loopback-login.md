# `tempogate login` — the loopback CLI flow

This document explains how a user obtains a personal Temporal JWT from a
laptop, how the loopback redirect works, and **why ephemeral loopback ports
work out of the box** without anyone touching a Google Cloud Console.

> **No browser on this host?** A remote SSH session, a cloud dev VM, or a CI
> debug shell cannot satisfy the loopback redirect because the browser sign-in
> needs to happen *on the same machine* as the CLI. For those, use
> `tempogate login --device` — the OAuth 2.0 device authorization grant
> ([RFC 8628]) — instead. See [cli-device-login.md](cli-device-login.md).

[RFC 8628]: https://datatracker.ietf.org/doc/html/rfc8628

## TL;DR

* `tempogate login` opens your browser, you sign in with Google through the
  tempogate issuer, and the CLI prints a short-lived JWT to stdout.
* The CLI talks **only to tempogate**, never directly to Google. Google only
  ever sees tempogate's single, fixed upstream callback.
* The `http://127.0.0.1:<port>/callback` redirect is therefore validated by
  **tempogate's own client registry**, not by Google's redirect-URI
  allowlist. The registration `http://127.0.0.1/callback` matches that exact
  path on any port (RFC 8252 §7.3), so a random ephemeral port each run is
  the default and needs no per-user registration anywhere.
* PKCE (RFC 7636, S256) is mandatory, the `state` echo is checked, and the
  listener is bound to `127.0.0.1` only.

## Why the loopback port "just works"

The canonical worry with native-app loopback logins (RFC 8252) is that the
identity provider requires every `http://127.0.0.1:<port>/...` redirect URI to
be pre-registered, and providers differ on whether they allow a fixed port,
any port, or a URI template. If that applied here, every downstream user would
have to register a set of loopback ports somewhere — exactly the friction an
open-source tool should avoid.

It does **not** apply here, because of where the loopback URI is checked:

```
  laptop                         tempogate                         Google
  ──────                         ─────────                         ──────
  tempogate login
     │  open browser
     ▼
  /authorize ─────────────────▶ validate client_id + redirect_uri
  redirect_uri =                against tempogate's client registry
  http://127.0.0.1:<port>/cb           │
                                        │ redirect, redirect_uri =
                                        ▼ https://tempogate.example.com/callback/google
                                                              ──────────────────▶ Google sign-in
                                        ◀────────────────────────────────────────  code
                                 exchange + domain allowlist
                                        │ mint our auth code
                                        ▼
  http://127.0.0.1:<port>/cb ◀── 302 with our code + state
     │ POST /token (PKCE verifier)
     ▼
  JWT
```

Google's `redirect_uri` is **always** tempogate's own
`https://<issuer>/callback/google` — one fixed URL the operator registers once
with their Google OAuth client. The `127.0.0.1` loopback URI never reaches
Google. tempogate validates it the same way it validates any downstream
client's redirect: against the registry described below, with the RFC 8252
loopback rule that only the port may vary.

So the loopback-port-registration question reduces to a one-line operator
config, and the CLI is free to pick a fresh ephemeral port every run.

## Operator setup

Register the CLI as a public client (no secret ⇒ PKCE mandatory) in
`OIDC_CLIENTS`, alongside any other clients:

```
OIDC_CLIENTS=tempogate-cli:http://127.0.0.1/callback,ui:https://temporal-ui.example.com/auth/sso/callback
```

The CLI's redirect URI is registered **without a port**. A loopback entry
(`http` with host exactly `127.0.0.1` or `[::1]`) matches the registered
scheme, host and path exactly and lets only the port vary, so:

* `http://127.0.0.1:54321/callback` ✅ matches (any ephemeral port).
* `http://127.0.0.1:@attacker.example/callback` ❌ the userinfo trick that
  sends the browser to `attacker.example`.
* `http://127.0.0.1.attacker.example:1234/callback` ❌ a different host.
* `http://localhost:54321/callback` ❌ `localhost` is not in the loopback
  class.
* `http://127.0.0.1:54321/callback/x` or `...?next=...` ❌ the path and
  (empty) query must match exactly.

Registering a port (`tempogate-cli:http://127.0.0.1:39473/callback`) is a
startup error, because it would look pinned while any port is accepted.
`tempogate login --port 39473` still works with the portless registration.
Upgrading from a release that used the prefix form `tempogate-cli:http://127.0.0.1:`
means replacing it with `tempogate-cli:http://127.0.0.1/callback`; the old
form is rejected at startup.

The signed-in email must also pass `OIDC_ALLOWED_DOMAINS`, the same gate the
Web UI flow uses.
What the token may do in Temporal comes from the server's
[authorization rules](authorization.md#authorization), and the default is
deny: an operator grants access with a rule such as
`OIDC_AUTHZ_RULES_0=email:alice@example.com=orders:write`.
An admitted user no rule matches gets no token; `tempogate login` exits
non-zero with
`access_denied: no Temporal access is granted to this account; ask an administrator for access`.
A rule change reaches an existing login at its next `tempogate token` refresh,
and removing someone's last grant makes that refresh fail with `invalid_grant`.

## Usage

```bash
export TEMPOGATE_ISSUER=https://tempogate.example.com

# Print a JWT (progress goes to stderr, so this captures just the token):
export TEMPORAL_AUTH_TOKEN=$(tempogate login)

tctl --tls_server_name temporal-frontend cluster health   # now authenticated
```

Flags:

| Flag          | Default                      | Notes                                                            |
| ------------- | ---------------------------- | ---------------------------------------------------------------- |
| `--issuer`     | `$TEMPOGATE_ISSUER`        | tempogate base URL. Required (flag or env).                      |
| `--port`       | `0`                         | Loopback port. `0` = a free ephemeral port (recommended).        |
| `--client-id`  | `tempogate-cli`             | Must match a registered `OIDC_CLIENTS` entry.                   |
| `--token-file` | `~/.tempogate/token.json`   | Where the token is persisted.                                    |
| `--insecure`   | `false`                     | Allow a plain-`http` issuer on a non-loopback host. Dev only.    |

`stdout` carries only the token; all human-facing text (the authorize URL,
progress, expiry) goes to `stderr`, so `$(tempogate login)` is safe in scripts.

### https issuers only

The issuer must be `https://`.
Plain `http://` is accepted only for a loopback host (`localhost`, `127.0.0.0/8`, `[::1]`), where the traffic never leaves the machine.
Any other plain-http issuer is refused by `tempogate login`, `tempogate login --device` and `tempogate token` before anything is sent, because the authorization code, the refresh token and the access token would cross the network in cleartext.
For a development stack on a trusted network (e.g. `http://tempogate:8000` inside Docker Compose), pass `--insecure` to `login` and to every `token` call:

```bash
tempogate login --insecure --issuer http://tempogate:8000
tempogate token --insecure --issuer http://tempogate:8000
```

`tempogate token` applies the check even when the stored token is still valid, so a missing `--insecure` shows up straight away rather than at the first refresh hours later.

The same rule covers redirects.
If the issuer (or a proxy in front of it) answers a CLI request with a redirect to plain `http` on a non-loopback host, the CLI stops with an error instead of following it, unless `--insecure` is passed.
A redirect to a different host is always refused: a `307`/`308` re-sends the request body, which holds the refresh token or the authorization code and PKCE verifier.
Same-host redirects, such as an `http` to `https` upgrade, are still followed.

## Persistence and `tempogate token`

`tempogate login` does not just print the token — it also writes the access
token, the refresh token, the absolute expiry, and the `client_id` they were
issued to to `~/.tempogate/token.json` (file mode `0600`, parent directory `0700`; the
write is atomic via a same-directory temp file + rename, so a crash never
leaves a half-written credential).

After that first login, use `tempogate token` for everything:

```bash
export TEMPOGATE_ISSUER=https://tempogate.example.com
export TEMPORAL_AUTH_TOKEN=$(tempogate token)
```

`tempogate token` reads the persisted file and:

* if the access token is **more than 5 minutes** from expiry, prints it
  immediately — a pure file read, no network, well under a second;
* if it is **within 5 minutes** of expiry, transparently exchanges the
  refresh token at `<issuer>/token` (`grant_type=refresh_token`), rewrites
  `token.json` with the rotated pair, and prints the fresh access token.
  The exchange presents the stored `client_id`, because the issuer only honours a refresh token for the client it was issued to.
  A `token.json` written by an older CLI has no `client_id`; the CLI then reads it from the access token's `client_id` claim, or from its `aud` for tokens minted before access tokens carried the Temporal audience.

Failure modes are explicit, never silent:

* no token file yet → a clear "run `tempogate login` first" error;
* a revoked / already-rotated / expired refresh token, a session past its
  absolute lifetime, or an email whose domain is no longer allowed → the
  renewal fails cleanly **without** overwriting the stored file or emitting
  the stale token, so nothing downstream acts on a credential the server has
  disowned. Run `tempogate login` again.

Refresh tokens are rotated on every exchange.
If a captured `token.json` is used after the legitimate CLI has refreshed, or the CLI refreshes after the thief has, the server sees an already-used token and revokes the whole session, so both parties are signed out.
A session also ends after `OIDC_REFRESH_MAX_LIFETIME` (default 7 days) from the original login, however often it is refreshed, and an operator can end it with `tempogate sessions revoke`.
Two `tempogate token` processes presenting the same refresh token would look like reuse too, so renewal is serialized.
`tempogate token` takes an exclusive lock on `<token-file>.lock` (created `0600` next to the token file and left in place) before refreshing, then re-reads the file: if another process refreshed while it waited, it prints that token instead of refreshing again.
This makes `tempogate token` safe to run concurrently, e.g. as a credential helper that tctl or the temporal CLI invokes in parallel.
A process waits at most 30 seconds for the lock and then fails with an error naming the lock file.
The lock is an `flock(2)` lock, released by the kernel if its holder dies, so a stale lock file never blocks anything.
The lock is implemented for Linux and macOS (the platforms tempogate ships for); on other platforms it is a no-op and concurrent refreshes can still end the session.

## Security properties

* **PKCE S256, mandatory.** The CLI is a public client: it generates a
  43-char (RFC 7636 §4.1 minimum) `code_verifier`, sends
  `BASE64URL(SHA256(verifier))` at `/authorize`, and presents the raw
  verifier at `/token`. An intercepted code cannot be redeemed.
* **`state` is checked.** A random 256-bit `state` is generated per run and
  constant-time compared on the callback.
  A callback with the wrong state is answered with an error page and otherwise ignored, so another local process or web page that finds the port cannot inject a code (CSRF / request-forgery defence) or abort the login; the genuine redirect still completes it.
* **One outcome.** Only the first callback with the right state is used; later ones (a reload, a second tab) get a "already handled" page and cannot stall the listener.
* **Loopback only.** The one-shot HTTP server binds `127.0.0.1`, so the
  callback is never reachable off-host.
* **https issuers.** Tokens are only sent to an `https` issuer, or to plain `http` on a loopback host, unless `--insecure` is passed (see [https issuers only](#https-issuers-only)).
* **Bounded wait.** If no code arrives within three minutes the command
  exits with a clear error rather than hanging the shell.
  Once the code arrives, the listener shuts down within two seconds even if a client connection stalls.
* **Short-lived, auto-renewed.** The minted access token follows the
  issuer's lifetime (`OIDC_ACCESS_TOKEN_TTL`, 4 hours by default); `tempogate token` renews it from the
  rotating refresh token five minutes before expiry, so a leaked access
  token has a bounded blast radius without forcing a re-login.
* **At rest.** The persisted credential is `0600` under a `0700` directory
  and written atomically; a rejected refresh never clobbers it.
