# Sign-in and authorization

Who can sign in, what their access token can do in Temporal, and how tempogate names them.
For the settings, see the [configuration reference](configuration.md).

## Hosted domain (Workspace mode)

`OIDC_ALLOWED_DOMAINS` checks only the domain of the email address.
That does not prove that your organization controls the Google account.
Anyone who can receive mail at an address can create a consumer Google account for it, and Google then reports `email_verified: true`.
Google recommends that you restrict access to an organization with the `hd` (hosted domain) claim.
Google sets it only for accounts that a Google Workspace or Cloud organization manages ([OpenID Connect docs](https://developers.google.com/identity/openid-connect/openid-connect)).

To require it, set `OIDC_ALLOWED_HOSTED_DOMAINS` to your Workspace primary domain (or several, comma-separated):

| Google account | `OIDC_ALLOWED_HOSTED_DOMAINS` empty | `OIDC_ALLOWED_HOSTED_DOMAINS=example.com` |
| --- | --- | --- |
| Workspace user `alice@example.com` (`hd=example.com`) | admitted | admitted |
| Consumer account for `alice@example.com` (no `hd`) | admitted | **rejected (403)** |
| Account in another Workspace (`hd=other.test`) with an allowed email | admitted | **rejected (403)** |

- All checks apply: `email_verified`, the email domain in `OIDC_ALLOWED_DOMAINS`, and the `hd` claim.
- `hd` is the primary domain of the organization. List it even when users sign in with a secondary or alias domain.
- Leave the setting empty only when your email is not on Google Workspace. tempogate then logs a warning at startup.
- tempogate also sends Google the `hd` request parameter (the domain when you configure one, `*` when several), so the account chooser shows the correct account. That parameter is only a UI hint, because the user can edit the request; the `hd` claim check is the control.

## Authorization

`OIDC_ALLOWED_DOMAINS` and [Workspace mode](#hosted-domain-workspace-mode) decide who can sign in.
Authorization rules decide what the access token of each person can do in Temporal, and **the default is deny**: a person that no rule grants anything gets no token.

```bash
OIDC_AUTHZ_RULES_0='email:alice@example.com=temporal-system:admin'
OIDC_AUTHZ_RULES_1='domain:example.com=orders:read,payments:read'
OIDC_AUTHZ_RULES_2='email:bob@example.com=orders:write'
```

or, in YAML:

```yaml
oidc:
  authz:
    rules:
      - "email:alice@example.com=temporal-system:admin"
      - "domain:example.com=orders:read,payments:read"
      - "email:bob@example.com=orders:write"
    default_permissions: ""
```

As for every list, the environment replaces the YAML list as a whole; it does not merge the entries.
In the Helm chart, set `authz.rules` and `authz.defaultPermissions`.

**Grammar.** A rule is `<selector>=<permission>[,<permission>...]`.

| Selector | Matches |
| --- | --- |
| `email:<address>` | The verified email of the signed-in Google account, exactly, case-insensitively. |
| `domain:<domain>` | The domain of that email, exactly (subdomains are other domains), case-insensitively. Without Workspace mode, a consumer Google account for an address at the domain also matches, so tempogate logs a warning for `domain:` rules when `OIDC_ALLOWED_HOSTED_DOMAINS` is empty. |

A permission is `<namespace>:<role>`, the shape of Temporal's `permissions` claim, with the role `read`, `write` or `admin`.
`temporal-system:<role>` grants that role on every namespace, and is the only way to grant cluster-level APIs such as `ListNamespaces`.
`group:` selectors (Google Workspace groups) are reserved, and tempogate refuses them for now.

**Semantics.**

- Every matching rule applies. tempogate merges their permissions, and a namespace that several rules name gets the highest role, in one claim entry.
- `OIDC_AUTHZ_DEFAULT_PERMISSIONS` applies only to an admitted person that no rule matches.
- An empty result is a denial, and tempogate mints no authorization code or token:
  - At sign-in, the Google callback sends the client `error=access_denied`. `tempogate login` prints it and exits.
  - The device verification page denies the device code, so `tempogate login --device` stops polling with `access_denied`.
  - On the device verification page, tempogate checks a sign-in session again before every approval.
- Only the access token has the permissions; the ID token never has them (see [Access tokens and ID tokens](configuration.md#access-tokens-and-id-tokens)).
- Integration keys from the admin API do not go through the rules. Each has the one namespace and role that it was minted with.

**Startup checks.** `tempogate serve` refuses to start when:

- a rule or the default is malformed, uses an unknown selector or `group:`, or names the `*` namespace (Temporal treats it as a namespace literally named `*`; use `temporal-system`);
- a rule or the default grants `worker`;
- neither rules nor a default are configured.

`worker` grants nothing under Temporal's default authorizer.
Worker is below Reader in Temporal's role bitmask ([`roles.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/roles.go#L9-L12)), and every API except health checks needs at least Reader.
Task-queue polling needs Writer ([`getRequiredRole`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_authorizer.go#L67-L77)), so grant workers `write`.

At startup, tempogate also:

- logs how many rules grant a `temporal-system` role;
- warns about rules whose domain is not in `OIDC_ALLOWED_DOMAINS` (nobody they select can sign in);
- warns when the default grants a `temporal-system` role (`every admitted user is cluster admin` for `admin`).

**Changes take effect at the next refresh.**
Rules are configuration, so a change needs a restart.
After that, every refresh resolves the permissions again, after the [domain re-check](operations.md#refresh-token-sessions).
A narrower grant mints a narrower token, and an empty one revokes the whole session (`invalid_grant`, logged as a `refresh_authz_denied` warning with the family id and email).
Access tokens already issued keep their permissions until they expire, so a change reaches a signed-in user within `OIDC_ACCESS_TOKEN_TTL` (4h) after the restart.
To end someone's sessions at once, [revoke them](operations.md#refresh-token-sessions) with `tempogate sessions revoke --email <e>` or `POST /admin/sessions/revoke`; access tokens already issued stay valid.

**Check a rule set.**
`tempogate authz explain --email <e>` reads the same configuration as `serve`.
It prints the matching rules, whether the default applied, and the permissions that the access token gets (or that the sign-in is denied).
It also flags an email whose domain is not in `OIDC_ALLOWED_DOMAINS`.

```bash
$ tempogate authz explain --email alice@example.com
email:        alice@example.com
matched:      rule 0  email:alice@example.com=temporal-system:admin
              rule 1  domain:example.com=orders:read,payments:read
permissions:  orders:read,payments:read,temporal-system:admin
```

**Namespace-scoped users and the Temporal Web UI.**
Temporal grants `ListNamespaces` only through a `temporal-system:<role>` permission.
It is a cluster-scoped API, so the default authorizer checks only the system role for it ([`metadata.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/api/metadata.go#L73), [`default_authorizer.go`](https://github.com/temporalio/temporal/blob/v1.32.1/common/authorization/default_authorizer.go#L47-L57), unchanged since v1.25).
A user with only `orders:read` thus cannot list namespaces, and the namespace dropdown of the Web UI stays empty for them.
They open their namespace by URL (`https://<temporal-ui>/namespaces/orders/workflows`), or you set the default namespace of the UI (`TEMPORAL_DEFAULT_NAMESPACE` for the `temporalio/ui` image) to the namespace that most users work in.
Do not grant `temporal-system:read` to fix the dropdown: it is read access to every namespace, workflow payloads included.
Revisit this if Temporal adds a grant that lists namespaces without access to their contents.

## Token subject

The `sub` of every token that tempogate mints for a person is `<connector>:<upstream sub>`; for Google, `google:<Google sub>`.
The connector is the one that the person signed in through.
The upstream `sub` is an opaque, stable id that Google never reuses.
The token also has the connector alone in an `idp` claim (`google`), and `/userinfo` returns both.
The connector is part of the identity, because the same upstream `sub` at two identity providers is two people; Google is the only connector today.

The email is in the `email` claim (the ID token also has `email_verified: true`).
Do not key users on the email: Google can give an address again to a different account, which then gets the identity of the previous holder.
Temporal's default claim mapper authorizes from `permissions`, not `sub`.
Integration keys do not change: their `sub` is still the owner of the key, and they have no `idp` claim.
