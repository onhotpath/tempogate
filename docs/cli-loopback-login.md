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
  **tempogate's own client registry prefix**, not by Google's redirect-URI
  allowlist. A random ephemeral port each run is the default and needs no
  per-user registration anywhere.
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
client's redirect: by prefix, against the registry described below.

So the loopback-port-registration question reduces to a one-line operator
config, and the CLI is free to pick a fresh ephemeral port every run.

## Operator setup

Register the CLI as a public client (no secret ⇒ PKCE mandatory) in
`OIDC_CLIENTS`, alongside any other clients:

```
OIDC_CLIENTS=tempogate-cli:http://127.0.0.1:,ui:https://temporal-ui.example.com/auth/sso/callback
```

The redirect prefix is `http://127.0.0.1:` — note the **trailing colon**. The
client registry matches `redirect_uri` by prefix, so:

* `http://127.0.0.1:54321/callback` ✅ matches (any ephemeral port).
* `http://127.0.0.1.attacker.example/callback` ❌ does **not** match — the
  next character after `127.0.0.1` must be `:`, not `.`.

If you prefer a fixed port, register `tempogate-cli:http://127.0.0.1:39473/`
and have users run `tempogate login --port 39473`.

The signed-in email must also pass `OIDC_ALLOWED_DOMAINS`, the same gate the
Web UI flow uses.

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

`stdout` carries only the token; all human-facing text (the authorize URL,
progress, expiry) goes to `stderr`, so `$(tempogate login)` is safe in scripts.

## Persistence and `tempogate token`

`tempogate login` does not just print the token — it also writes the access
token, the refresh token, and the absolute expiry to
`~/.tempogate/token.json` (file mode `0600`, parent directory `0700`; the
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

Failure modes are explicit, never silent:

* no token file yet → a clear "run `tempogate login` first" error;
* a revoked / already-rotated / expired refresh token → the renewal fails
  cleanly **without** overwriting the stored file or emitting the stale
  token, so nothing downstream acts on a credential the server has disowned.

Refresh tokens are rotated on every exchange (the server invalidates the old
one), so a captured `token.json` is usable at most until the next refresh.

## Security properties

* **PKCE S256, mandatory.** The CLI is a public client: it generates a
  43-char (RFC 7636 §4.1 minimum) `code_verifier`, sends
  `BASE64URL(SHA256(verifier))` at `/authorize`, and presents the raw
  verifier at `/token`. An intercepted code cannot be redeemed.
* **`state` is checked.** A random 256-bit `state` is generated per run and
  constant-time compared on the callback; a mismatch aborts the login
  (CSRF / request-forgery defence).
* **Loopback only.** The one-shot HTTP server binds `127.0.0.1`, so the
  callback is never reachable off-host.
* **Bounded wait.** If no code arrives within three minutes the command
  exits with a clear error rather than hanging the shell.
* **Short-lived, auto-renewed.** The minted access token follows the
  issuer's lifetime (4 hours in v1); `tempogate token` renews it from the
  rotating refresh token five minutes before expiry, so a leaked access
  token has a bounded blast radius without forcing a re-login.
* **At rest.** The persisted credential is `0600` under a `0700` directory
  and written atomically; a rejected refresh never clobbers it.
