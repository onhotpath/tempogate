# Upgrading

This page lists what you must change when you upgrade tempogate.
Do the steps in sequence.

## v0.2.0 to v0.3.0

v0.3.0 has many breaking changes.
Most of them make the defaults safer, so a v0.2.0 configuration does not start without changes.

### 1. Before you upgrade

1. Back up the state database (the SQLite file, or the PostgreSQL database).
2. Configure authorization.
   v0.2.0 gave every admitted person cluster admin; v0.3.0 denies by default, and `serve` does not start without rules.
   - Set `OIDC_AUTHZ_RULES_<n>`, or set `OIDC_AUTHZ_DEFAULT_PERMISSIONS`.
   - To keep the v0.2.0 behaviour while you write rules, set `OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin`.
   - See [Upgrading to deny-by-default authorization](#upgrading-to-deny-by-default-authorization).
3. Make `OIDC_ISSUER` an `https://` URL.
   `serve` refuses a plain-http issuer on a host that is not loopback.
   For a development stack only, set `OIDC_ALLOW_INSECURE_ISSUER=true`.
4. Change every `OIDC_CLIENTS` entry to an exact redirect URI.
   Prefix entries stop the server at startup.
   - Replace `tempogate-cli:http://127.0.0.1:` with `tempogate-cli:http://127.0.0.1/callback`.
   - Give every other client its full callback URI, for example `tempogate-device-ui:<issuer>/device/sso-callback`.
   - For plain-http redirect URIs in a development stack only, set `OIDC_ALLOW_INSECURE_REDIRECT_URIS=true`.
   - See [Redirect URI registration](configuration.md#redirect-uri-registration).
5. Configure the admin API.
   Without these settings the admin API answers 401 to every call except `/admin/healthz`.
   - Set `ADMIN_TOKEN_SHA256` to the SHA-256 of an admin token, and send that token as a bearer token.
   - For a bind that is not loopback, set `ADMIN_ALLOWED_HOSTS` to the host names that your callers use.
   - To mint `temporal-system` keys, set `ADMIN_ALLOW_SYSTEM_GRANTS=true`.
   - See [Admin API](configuration.md#admin-api).
6. If you keep `application.yaml` in a parent directory of the working directory, move it, or pass `--config <path>` or `TEMPOGATE_CONFIG`.
   tempogate no longer searches parent directories.
7. If you set `API_DOCS_ENABLED=true` with an `https://` issuer, remove it.
   `serve` does not start with it, and `tempogate gen-oas` prints the same specs.
8. Recommended: set `OIDC_ALLOWED_HOSTED_DOMAINS` for Google Workspace ([Workspace mode](authorization.md#hosted-domain-workspace-mode)), and `KEYS_ENCRYPTION_KEY` ([Signing-key encryption](hardening.md#signing-key-encryption)).

To check the rules before the upgrade, run `tempogate authz explain --email <e>` from the v0.3.0 binary with the new configuration.

### 2. Upgrade

1. Run `tempogate migrate` before `serve`.
   It applies migrations `0010` to `0016`.
   The Helm chart runs it in an initContainer.
2. Start `tempogate serve`.

Migration `0012` deletes the stored refresh tokens, authorization codes, device codes and browser sessions, because SQLite cannot hash them in place.
So every user signs in once more after the upgrade.

### 3. What changes for users and clients

**Tokens.**

- The `sub` of a person's token is now `google:<Google sub>`, not the email.
  If you key users on `sub`, re-key them, or use the `email` claim. A new `idp` claim holds the connector (`google`).
  See [Token subject](authorization.md#token-subject).
- The access token and the ID token are now separate.
  The access token has `aud` set to `OIDC_ACCESS_TOKEN_AUDIENCE` (default `temporal`), and it no longer carries `nonce`.
  A client that sent the ID token to Temporal as a bearer token must send the access token.
  See [Access tokens and ID tokens](configuration.md#access-tokens-and-id-tokens).
- `/userinfo` refuses ID tokens, and tokens minted before the upgrade.
- After `redirect_uri` validation, `/authorize` reports errors as a 302 redirect, not as JSON.

**Sessions.**

- A session ends 7 days after sign-in (`OIDC_REFRESH_MAX_LIFETIME`), or after 7 idle days (`OIDC_REFRESH_TOKEN_TTL`).
  To keep a 30-day session, set `OIDC_REFRESH_MAX_LIFETIME=720h`.
- A session also ends when its email domain leaves `OIDC_ALLOWED_DOMAINS`, when the rules no longer grant anything, or when a rotated refresh token is used again.
- Migration `0011` keeps existing sessions. Each existing refresh token becomes its own family, with its sign-in time set to its last refresh, so it ends at most `OIDC_REFRESH_MAX_LIFETIME` later.
- See [Refresh-token sessions](operations.md#refresh-token-sessions).

**Integration keys.**

- `POST /admin/keys` requires `expires_at`, at most `ADMIN_KEYS_MAX_TTL` (default 90 days) in the future.
- `"role": "worker"` now gets 422. Mint `write` for workers, because task-queue polling is a write API.
- Keys minted before the upgrade have no `aud`. Mint them again before you enable the audience check of Temporal (`global.authorization.audience`, Temporal v1.29.0+).
- Keys minted before the upgrade without `expires_at` stay valid at Temporal until you retire their signing key.
  See [Upgrading to required key expiry](#upgrading-to-required-key-expiry).

**CLI.**

- `tempogate login` and `tempogate token` need `--insecure` for a plain-http issuer on a host that is not loopback.

**HTTP surface.**

- `/openapi.json`, `/openapi.yaml`, `/docs` and `/schemas/*` answer 404, unless `API_DOCS_ENABLED=true` on a plain-http issuer.
- JSON bodies no longer include `$schema`, and the public `/healthz` no longer includes `version`.

**Signing keys.**

- After you encrypt a signing key with `KEYS_ENCRYPTION_KEY`, tempogate needs that key to start.
  A rollback to v0.2.0 then fails at startup.

### Upgrading to deny-by-default authorization

Releases without authorization rules gave every admitted person `temporal-system:admin`.
That is no longer the default: with no rules and no default, `tempogate serve` stops at startup with `authz: no authorization configured`.

- To keep the previous behaviour while you write rules, set `OIDC_AUTHZ_DEFAULT_PERMISSIONS=temporal-system:admin` (chart: `authz.defaultPermissions: "temporal-system:admin"`).
  tempogate logs a warning at every start that every admitted user is cluster admin.
- To move to rules, list the people who need cluster admin with `email:` rules, grant everyone else what they need per namespace, and leave the default empty.
  Check the result with `tempogate authz explain --email <e>` before you restart.
- Existing sessions keep working: their next refresh mints a token with the new permissions, or ends the session if the person gets nothing.
  Access tokens issued before the upgrade keep `temporal-system:admin` until they expire (`OIDC_ACCESS_TOKEN_TTL`); a session revoke (`tempogate sessions revoke`, `POST /admin/sessions/revoke`) only stops their renewal.

### Upgrading to required key expiry

`POST /admin/keys` now refuses a body without `expires_at` (400), and `expires_at` can be at most `ADMIN_KEYS_MAX_TTL` (default 90 days) in the future.
Callers that relied on long-lived keys must send an expiry, and mint again before it.
tempogate does not change keys minted earlier without `expires_at`: their JWT has no `exp`, so they stay valid at Temporal until you retire their signing key.
To end them, follow the rotation runbook above; `GET /admin/keys` lists them with no `expires_at`.
`tempogate migrate` adds the `retired_at` column (migration 0013), and keeps existing keys active.
