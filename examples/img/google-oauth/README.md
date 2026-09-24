# Screenshots — google-oauth-setup.md

These back `../../google-oauth-setup.md`. All use a throwaway project and
`tempogate.example.com`; the client id/secret in `04-credentials.png` are
dummy placeholders (no real secret).

| File | Shows |
| --- | --- |
| `01-project.png` | Google Cloud Console "Select a resource" — project picker / "New project". |
| `02-consent-screen-branding.png` | Google Auth Platform → Branding: app name + user support email. |
| `02-consent-screen-audience.png` | Google Auth Platform → Audience: User type (Internal/External) + publishing status. |
| `03-redirect-uri.png` | Create OAuth client ID — Application type = Web application, Authorized redirect URI = `OIDC_ISSUER` + `/callback/google`. |
| `04-credentials.png` | "OAuth client created" — Client ID + Client secret (dummy/redacted). |
