package sqlite

import (
	"context"
	"time"

	"go.uber.org/fx"

	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

type Params struct {
	fx.In

	Lifecycle fx.Lifecycle

	Path        string        `name:"sqlite_path"`
	MaxConns    int           `name:"sqlite_max_conns"`
	BusyTimeout time.Duration `name:"sqlite_busy_timeout"`
}

func newFx(p Params) (*Store, error) {
	s, err := New(
		WithPath(p.Path),
		WithMaxConns(p.MaxConns),
		WithBusyTimeout(p.BusyTimeout),
	)
	if err != nil {
		return nil, err
	}

	p.Lifecycle.Append(fx.Hook{
		OnStop: func(_ context.Context) error { return s.Close() },
	})
	return s, nil
}

// Fx registers the sqlite store as *Store (for direct callers like
// cmd/serve.go) plus every consumer-side interface it satisfies
// (keys.KeyStore, keys.DenylistChecker, oidc.AuthRequestStore,
// oidc.BrowserSessionStore, oidc.CallbackStore, oidc.TokenStore,
// oidc.DeviceCodeStore), using a single underlying constructor.
// admin.KeyRegistry is provided as a separate adapter constructor (see
// admin_adapter.go) because its short method names
// (Save/ByID/List/MarkRevoked) deliberately differ from the prefixed
// methods on *Store (SaveIntegrationKey, ...) to allow multiple consumers
// to share short names without colliding on the same struct.
//
// keys.DenylistChecker happens to use the bare name IsRevoked — which lines
// up with Store.IsRevoked — so a direct fx.As binding suffices without an
// adapter shim. (See state/doc.go for the prefixed-vs-short naming rule.)
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newFx,
				fx.As(new(keys.KeyStore)),
				fx.As(new(keys.DenylistChecker)),
				fx.As(new(oidc.AuthRequestStore)),
				fx.As(new(oidc.BrowserSessionStore)),
				fx.As(new(oidc.CallbackStore)),
				fx.As(new(oidc.TokenStore)),
				fx.As(new(oidc.DeviceCodeStore)),
				fx.As(fx.Self()),
			),
		),
		fx.Provide(newAdminKeyRegistry),
	)
}
