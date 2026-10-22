package google

import (
	"log/slog"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/oidc"
)

type params struct {
	fx.In

	Logger *slog.Logger

	ClientID      string `name:"google_client_id"`
	ClientSecret  string `name:"google_client_secret"`
	AuthEndpoint  string `name:"google_auth_endpoint"`
	TokenEndpoint string `name:"google_token_endpoint"`
	IssuerURL     string `name:"google_issuer_url"`
	HostedDomains string `name:"oidc_allowed_hosted_domains"`

	Observer oidc.UpstreamObserver `optional:"true"`
}

// newFx builds the Google connector. Without OIDC_ALLOWED_HOSTED_DOMAINS the
// gate is the email domain alone, which a consumer Google account for an
// allowed address passes; that is a supported setup (e.g. mail not hosted on
// Google Workspace) but it is warned about at startup so it is a visible
// choice rather than a silent default.
func newFx(p params) (*Connector, error) {
	if len(oidc.ParseDomains(p.HostedDomains)) == 0 {
		p.Logger.Warn("OIDC_ALLOWED_HOSTED_DOMAINS is not set: the Google sign-in gate relies on the email domain only, "+
			"which consumer Google accounts created for an allowed address also pass; "+
			"set OIDC_ALLOWED_HOSTED_DOMAINS to your Google Workspace domain(s) to require the hd claim",
			"op", "oidc.callback",
		)
	}
	client := New(p.ClientID, p.ClientSecret, p.TokenEndpoint, p.IssuerURL, WithObserver(p.Observer))
	return NewConnector(Config{
		ClientID:      p.ClientID,
		AuthEndpoint:  p.AuthEndpoint,
		IssuerURL:     p.IssuerURL,
		HostedDomains: p.HostedDomains,
	}, client)
}

// Fx contributes the Google connector to the oidc_connectors group package
// oidc collects. The consumer depends only on its own interface; this
// binding is the sole place the two are tied together.
func Fx() fx.Option {
	return fx.Provide(
		fx.Annotate(
			newFx,
			fx.As(new(oidc.Connector)),
			fx.ResultTags(`group:"oidc_connectors"`),
		),
	)
}
