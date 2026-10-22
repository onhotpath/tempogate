# `tempogate login --device` — the device-code CLI flow

This document explains how a user obtains a personal Temporal JWT from a
shell that has **no local browser** — a remote SSH session, a cloud-hosted dev
VM, a CI debug shell, a tablet SSH-ed into a workstation — using the OAuth 2.0
device authorization grant ([RFC 8628]).

[RFC 8628]: https://datatracker.ietf.org/doc/html/rfc8628

## TL;DR

* `tempogate login --device` prints a short, human-typable `user_code` (e.g.
  `BCDF-GHJK`) and a verification URL. On any device with a browser, you open
  the URL, sign in via Google through tempogate, **visually verify the code
  matches**, and click Approve. The CLI's polling loop returns and persists a
  token identical in shape and lifetime to a loopback login.
* The persisted token (`~/.tempogate/token.json`) and the `tempogate token`
  auto-refresh path are unchanged from the [loopback flow](cli-loopback-login.md);
  only the initial acquisition differs.
* The `user_code` charset is RFC 8628 §6.1 base20 (no vowels) plus four
  unambiguous digits — `BCDFGHJKLMNPQRSTVWXZ` + `3479` — so no `0/O`, `1/I`,
  `5/S`, `6/G`, `8/B`, `2/Z` look-alike pairs survive a hand-copy.

## When to use this

Use `--device` when **the shell running `tempogate login` cannot open a browser
window on the same machine that will sign in**. Typical cases:

* SSH'd into a remote box (a cloud dev VM, a jumphost, an AI coding agent's VM).
* A CI job's debug shell where Google sign-in needs to happen on your laptop.
* An iPad or phone shell into a workstation.

**Prefer the [loopback flow](cli-loopback-login.md) on a laptop with a browser.**
It is a single command (no copy-paste between devices), has a tighter
end-to-end UX, and does not require the operator to register a second client
on the server.

## Quick start

```bash
export TEMPOGATE_ISSUER=https://tempogate.example.com

tempogate login --device
```

Output (token goes to stdout, progress to stderr — `$(tempogate login --device)`
captures only the token):

```
A login URL has been generated. On any device with a browser, open:

  https://tempogate.example.com/device

And enter this code:

  BCDF-GHJK

(or, to skip the manual entry, scan/open:
  https://tempogate.example.com/device?user_code=BCDF-GHJK )

Waiting for you to approve in your browser…
Signed in. Token saved to /home/you/.tempogate/token.json, valid until 2026-05-24T18:42:00Z.
```

`TEMPOGATE_LOGIN_MODE=device` is equivalent to `--device`, for CI scripts that
cannot pass flags. After this first login, use `tempogate token` exactly as
with the loopback flow — same file, same auto-refresh, no further browser
involvement.

The `verification_uri_complete` line — the shortcut URL with the code
pre-filled — is shown only if your server publishes one; servers are free to
omit it (RFC 8628 §3.2 marks it OPTIONAL), in which case the bare
`verification_uri` and the typed code are your only path. tempogate publishes
both. `--port` and `--client-id`'s default are repurposed under `--device`:
the loopback port is ignored, and the default client_id switches from
`tempogate-cli` to `tempogate-device`. A `--device-poll-deadline` flag caps
how long the CLI keeps polling — useful in CI to fail fast; without it, the
CLI follows the issuer's advertised `expires_in`.

The issuer must be `https://` (or plain `http://` on a loopback host), as for the loopback flow.
For a plain-http development stack, pass `--insecure`; see [https issuers only](cli-loopback-login.md#https-issuers-only).

## What happens in your browser

When you open the URL on a second device:

1. **You are bounced through Google sign-in.** The verification page requires
   an authenticated tempogate session, and tempogate establishes one by
   sending you through its own `/authorize` chain — the same Google SSO path
   the Web UI uses, with the same `OIDC_ALLOWED_DOMAINS` domain gate. No new
   sign-in machinery: a session at `/device*` is just a token from
   tempogate's existing OIDC pipeline, scoped to the device-flow cookie.
2. **The confirmation page shows the user_code prominently.** If you arrived
   via `verification_uri_complete` (the URL containing `?user_code=…`), the
   code is shown for confirmation; if you arrived via the bare
   `verification_uri`, you type the code into a single field. Either way, the
   page renders the code in a large, fixed-width font.
3. **You visually verify the code matches what your terminal is showing**,
   then click **Approve** (or **Deny** to abort).

**Always check the code match before approving.** The verification URL on its
own is not the authorization grant — anyone who tricked you into opening a
URL with their `user_code` could otherwise approve their session against your
Google identity. The human visual check is the binding step; treat it the way
you would treat a 2FA prompt that did not originate from an action you just
took.

## Polling, `slow_down`, deadlines

The CLI polls `POST /token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code` at the interval the
server advertised in its initial `/device_authorization` response (`interval`
field, seconds). Each poll resolves to one of:

| Server response       | Meaning                                                      | CLI behaviour                                           |
| --------------------- | ------------------------------------------------------------ | ------------------------------------------------------- |
| `authorization_pending` | Still waiting for the human to Approve.                    | Sleep `interval` seconds, poll again.                   |
| `slow_down`           | Polling faster than the server's published interval.         | Bump local interval **+5 s** (per RFC 8628 §3.5), poll again. |
| `access_denied`       | Human clicked **Deny**, or no [authorization rule](authorization.md#authorization) grants the signed-in account anything. | Exit non-zero with `the device authorization was denied`. |
| `expired_token`       | Device-code TTL elapsed before approval (`expires_in`).      | Exit non-zero, suggest re-running the command.          |
| `invalid_grant`       | Server lost the `device_code` (storage rotated, manual revoke). | Exit non-zero.                                       |
| Token response        | Approved. Same shape and TTL as a loopback-login token.      | Print to stdout, persist via `cli.Save`, exit zero.     |

The server enforces `slow_down` from its own clock: each `/token` poll records
`last_polled_at` against the stored `device_code` row, and if two
polls arrive faster than the published interval the second returns `slow_down`
**and** the stored interval is bumped +5 s — so a misbehaving client converges
on a polite cadence after a couple of round-trips rather than starving the
endpoint.
The check and the record are one atomic step, so polls fired in parallel do not slip through together: of several polls inside one interval, at most one gets a real answer and the rest get `slow_down`.

The whole flow has one hard deadline: `expires_in` (the device-code TTL the
server returned in its initial response). When that elapses, polling returns
`expired_token` and the CLI exits. Re-run `tempogate login --device` to start
a fresh flow.

## Operator setup

Register **two** new clients in `OIDC_CLIENTS`, on top of any existing entries
(here alongside the loopback CLI):

```
OIDC_CLIENTS=\
  tempogate-cli:http://127.0.0.1/callback,\
  tempogate-device:,\
  tempogate-device-ui:https://tempogate.example.com/device/sso-callback
```

| client_id              | Visibility | Why it exists                                                                             |
| ---------------------- | ---------- | ----------------------------------------------------------------------------------------- |
| `tempogate-device`     | external   | The public client the CLI presents at `/device_authorization` and `/token`. Registered with an empty value, which makes it **device-only**: it may use the device authorization grant and refresh tokens, and `/authorize` refuses it with `unauthorized_client`. A client registered with redirect URIs is likewise refused at `/device_authorization`, and `/token` refuses either kind a grant it is not registered for. |
| `tempogate-device-ui`  | internal   | Confidential client that tempogate **uses as a client of itself** to drive the verification page through `/authorize` + Google SSO. Its callback is `<issuer>/device/sso-callback`. |

tempogate checks at startup that `tempogate-device-ui` is registered for exactly `<issuer>/device/sso-callback` (for a loopback issuer such as `http://127.0.0.1:8000`, the port-less `http://127.0.0.1/device/sso-callback` also matches) and refuses to boot otherwise, since `/authorize` would reject every verification bounce.

`tempogate-device-ui` is confidential — register a secret for it:

```
OIDC_CLIENT_SECRETS=\
  temporal-ui:…existing…,\
  tempogate-device-ui:<32+ bytes of base64url randomness, operator-managed>
```

The device flow also introduces a short-lived browser session at
`/device*`, signed by an HMAC key the operator supplies:

```
# Base64url-encoded 32 bytes of randomness:
OIDC_SESSION_SIGNING_KEY=$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')
OIDC_SESSION_TTL=5m   # default; the verification cookie's lifetime
```

`OIDC_SESSION_SIGNING_KEY` is required at startup — tempogate refuses to
boot if it is empty, not base64url, or does not decode to exactly 32 bytes
(the HMAC-SHA256 key length). Both secrets above (`tempogate-device-ui`'s
entry in `OIDC_CLIENT_SECRETS` and `OIDC_SESSION_SIGNING_KEY`) must be
**stable across rolling restarts** — rotating them invalidates active
approval sessions, so users mid-flow will see their verification page expire.

The signed-in email is gated by `OIDC_ALLOWED_DOMAINS`, the same allowlist
the loopback flow and the Web UI use. The token carries the permissions the
server's [authorization rules](authorization.md#authorization) grant the
account, the same as a loopback login; per-namespace scope downgrade on the
approve page is not in this release. An admitted account no rule grants
anything to is shown an "Access denied" page instead of the approve prompt,
the device code is denied, and the CLI exits with `access_denied`. The page
re-checks the rules before every approval, so a verification-page session
does not outlive a removed rule. Grant access with a rule such as
`OIDC_AUTHZ_RULES_0=email:alice@example.com=orders:write`.

## Security notes

* **The user_code is short by design.** It is meant to be human-typeable.
  Protection against guessing comes from a short TTL (`expires_in`,
  15 minutes), attempt limits on the verification page (below), one
  uniform message for every unusable code, and the human visually
  verifying the code matches before approving.
* **User-code attempts are rate limited (RFC 8628 §5.1).** Every page that
  looks a code up (`POST /device`, `/device/confirm`, `/device/approve`,
  `/device/deny`) counts **failed** lookups against two budgets: 20 per
  minute per client IP and 5 per minute per verification session.
  A code that turns out valid costs nothing, so honest users behind one NAT
  do not throttle each other.
  Once a budget is spent the page answers `429 Too Many Requests` with
  "Too many attempts. Wait a minute, then try again." for any code, live or
  not, so a throttled guesser learns nothing; the budget refills
  continuously over the minute.
  An unknown, expired, approved or denied code all get the same "That code
  is not valid" page, so a guess cannot tell a real code from a dead one.
  The limits are fixed (not configurable) and kept in memory per replica,
  so N replicas allow up to N times the budget, which is still far from
  useful against ~36.6 bits of user_code.
  The client IP is the TCP peer address; `X-Forwarded-For` is not trusted.
  Behind a reverse proxy or load balancer every client therefore shares the
  proxy's IP budget, and the per-session budget is what tells signed-in
  users apart.
  The flip side: one client submitting bad codes through that proxy can
  briefly throttle code entry for everyone else behind it, until the
  budget refills.
* **Approve and Deny must be same-origin.** The POST needs a matching
  `Origin`, or, when a browser omits it, a `Referer` on the issuer's scheme
  and host whose path sits under the issuer's path.
  The `Referer` is parsed, not prefix-matched, so
  `https://tempogate.example.com.evil.com/` does not pass.
* **The verification URL is safe to share, the `device_code` is not.**
  The URL only lets someone *enter* a code; without the `device_code`
  itself (which lives only on the CLI host) the polling endpoint cannot be
  redeemed for a token. Do not paste the JSON response from
  `/device_authorization` into chat.
* **The verification cookie is tightly scoped.** It is HttpOnly,
  `SameSite=Lax`, signed (not encrypted), path-scoped to the device-flow
  verification UI (`<issuer-path>/device`, so `/device` at a root issuer),
  and has the TTL set by `OIDC_SESSION_TTL` (default 5m).
  It is `Secure` whenever `OIDC_ISSUER` is https; a plain-http issuer (local
  or docker-compose only) gets a non-`Secure` cookie, since a browser would
  never send a `Secure` one back over http.
  It is *not* a general-purpose tempogate login session — the only thing it
  authorizes is approving or denying a pending device flow.
* **One key, separate MACs.** `OIDC_SESSION_SIGNING_KEY` signs both the
  session cookie and the SSO-bounce `state`, each under its own label
  (`tempogate/session-cookie`, `tempogate/device/bounce-state`), so a value
  minted for one never verifies as the other.
  Upgrading from a release without the labels invalidates cookies and
  bounce states issued before the upgrade; both live minutes, and an
  affected user just restarts the sign-in.
* **The minted token is identical to a loopback token.** Same lifetime,
  same `permissions` claim, same Temporal `aud`, same JWKS-verified signature. The
  device flow changes *how* the human authenticates the CLI, not what the
  CLI gets.
* **https only, unless `--insecure`.** The `device_code` and the tokens are refused to a plain-http issuer on a non-loopback host before any request is sent.
* **PKCE does not apply.** RFC 8628 §5.1 binds the grant to the
  `device_code` itself (a server-issued opaque value) rather than to a
  client-generated verifier. Tempogate honours that: the `device_code` is
  single-use and consumed on first redemption, whether the redemption
  succeeds, errors, or is denied.

## See also

* [docs/cli-loopback-login.md](cli-loopback-login.md) — the laptop flow, the
  shared persistence and auto-refresh layer.
* [docs/getting-started.md](getting-started.md) — the same demo stack with
  the device flow enabled.
* [docs/configuration.md](configuration.md) — every env var, including
  `OIDC_SESSION_TTL` and `OIDC_SESSION_SIGNING_KEY`.
