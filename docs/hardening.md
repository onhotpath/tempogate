# Hardening

How tempogate protects its public endpoints and its stored secrets.
To report a vulnerability, see [SECURITY.md](../SECURITY.md).

## Abuse controls

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

## Signing-key encryption

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
