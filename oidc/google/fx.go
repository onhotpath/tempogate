package google

import (
	"strings"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/oidc"
)

type params struct {
	fx.In

	Issuer        string `name:"oidc_issuer"`
	ClientID      string `name:"google_client_id"`
	ClientSecret  string `name:"google_client_secret"`
	TokenEndpoint string `name:"google_token_endpoint"`
	IssuerURL     string `name:"google_issuer_url"`
}

func newFx(p params) *Client {
	redirectURL := strings.TrimRight(p.Issuer, "/") + oidc.CallbackPath
	return New(p.ClientID, p.ClientSecret, p.TokenEndpoint, redirectURL, p.IssuerURL)
}

// Fx provides the Google client as oidc.Upstream. The consumer (package
// oidc) depends only on its own interface; this binding is the sole place
// the two are tied together, mirroring state/sqlite's fx.As wiring.
func Fx() fx.Option {
	return fx.Provide(
		fx.Annotate(
			newFx,
			fx.As(new(oidc.Upstream)),
		),
	)
}
