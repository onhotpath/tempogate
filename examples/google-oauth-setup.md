# Creating the upstream Google OAuth client

tempogate federates sign-in to Google: it is an OAuth2 *client* of Google and
an OIDC *provider* to Temporal. This page creates that upstream Google client.
You only need it for a real deployment — the
[docker-compose example](docker-compose/README.md) ships a mock IdP and needs
none of this.

Time: ~5 minutes. You need a Google account; for the domain gate to be
meaningful, a Google Workspace org whose email domain you control.

## 1. Pick or create a project

In the [Google Cloud Console](https://console.cloud.google.com/), select an
existing project or create one (any name; it only scopes the OAuth client).

![Google Cloud project selector](img/google-oauth/01-project.png)

## 2. Configure the OAuth consent screen

Under **Google Auth Platform** (the console reorganized this from the older
"APIs & Services → OAuth consent screen"; settings are the same, split across
two pages).

**Branding** — app name and user support email. Anything recognizable; users
see these on the Google consent page. Scopes need nothing here: tempogate
requests `openid` and `email` at runtime, not preselected.

![Google Auth Platform — Branding](img/google-oauth/02-consent-screen-branding.png)

**Audience** — *User type*. *Internal* if every user shares your Workspace org
(simplest — no verification, no test-user list). *External* otherwise; while
in *Testing* you must add each user under *Test users*.

![Google Auth Platform — Audience](img/google-oauth/02-consent-screen-audience.png)

> The domain gate that actually controls who gets in is tempogate's
> `OIDC_ALLOWED_DOMAINS`, applied to Google's verified email **after**
> sign-in — not this screen. Consent-screen *Internal* and
> `ALLOWED_DOMAINS` are independent layers; set both.
>
> If your users are in Google Workspace, also set
> `OIDC_ALLOWED_HOSTED_DOMAINS` to your Workspace primary domain.
> The email domain alone does not prove your organization manages the
> account: anyone can create a consumer Google account for an address
> they receive mail at. With it set, tempogate requires Google's `hd`
> claim to match. See
> [Hosted domain (Workspace mode)](../docs/configuration.md#hosted-domain-workspace-mode).

## 3. Create an OAuth client ID

**Google Auth Platform → Clients → Create client** (formerly "APIs &
Services → Credentials → Create credentials → OAuth client ID").

- **Application type:** **Web application** (tempogate runs the
  authorization-code flow server-side).
- **Authorized JavaScript origins:** not required by tempogate — there is no
  browser-side Google call. Leave it empty, or set it to the issuer origin
  (`https://tempogate.example.com`); either works.
- **Authorized redirect URIs:** add exactly **tempogate's issuer + `/callback/google`**:

  | tempogate `OIDC_ISSUER` | Authorized redirect URI |
  | --- | --- |
  | `https://tempogate.example.com` | `https://tempogate.example.com/callback/google` |
  | `https://tempogate.example.com/idp` (sub-path hosting) | `https://tempogate.example.com/idp/callback/google` |
  | `http://tempogate:8000` (local, /etc/hosts demo) | `http://tempogate:8000/callback/google` |

  It must match the issuer **scheme, host, port, and path** byte for byte —
  this is the single most common setup mistake (`redirect_uri_mismatch`).

![Authorized redirect URI entry](img/google-oauth/03-redirect-uri.png)

## 4. Copy the credentials into tempogate

Google shows a **Client ID** and **Client secret**. They map to:

| Google value | tempogate env var | Helm value |
| --- | --- | --- |
| Client ID | `OIDC_GOOGLE_CLIENT_ID` | `auth.upstream.google.clientIdSecretRef` |
| Client secret | `OIDC_GOOGLE_CLIENT_SECRET` | `auth.upstream.google.clientSecretSecretRef` |

![Client ID and secret](img/google-oauth/04-credentials.png)

The Helm chart never templates secret material — create a Kubernetes Secret
and reference it (see the [chart README](../charts/tempogate/README.md#secrets)).
Never commit the client secret.

## 5. Verify

Set the four required SSO env vars (`OIDC_ISSUER`, `OIDC_CLIENTS`,
`OIDC_ALLOWED_DOMAINS`, and the two `OIDC_GOOGLE_*` credentials — full
reference in [docs/configuration.md](../docs/configuration.md)), plus
`OIDC_ALLOWED_HOSTED_DOMAINS` for a Workspace organization, start
tempogate, and complete a Web UI or `tempogate login` sign-in. A
`redirect_uri_mismatch` from Google means step 3's URI does not exactly equal
`OIDC_ISSUER` + `/callback/google`.

tempogate sends Google its own PKCE challenge and nonce and binds each login
to the browser that started it with a short-lived cookie; there is nothing to
configure for either in the Google console. A `400` from `/callback/google`
saying the sign-in "was not started in this browser" means the callback
arrived without that cookie: the login was started in another browser or
profile, cookies are blocked for the tempogate host, or a proxy rewrote the
path so the browser did not send it. See
[Google leg](../docs/configuration.md#google-leg).

The end-to-end walkthrough is [docs/getting-started.md](../docs/getting-started.md).
