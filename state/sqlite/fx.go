package sqlite

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

type Params struct {
	fx.In

	Lifecycle fx.Lifecycle
	Logger    *zap.Logger `optional:"true"`

	Path        string        `name:"sqlite_path"`
	MaxConns    int           `name:"sqlite_max_conns"`
	BusyTimeout time.Duration `name:"sqlite_busy_timeout"`

	Observer ErrorObserver `optional:"true"`
}

func newFx(p Params) (*Store, error) {
	opts := []Option{
		WithPath(p.Path),
		WithMaxConns(p.MaxConns),
		WithBusyTimeout(p.BusyTimeout),
		WithErrorObserver(p.Observer),
	}
	if p.Logger != nil {
		opts = append(opts, WithLogger(p.Logger.Named("sqlite")))
	}
	s, err := New(opts...)
	if err != nil {
		return nil, err
	}

	p.Lifecycle.Append(fx.Hook{
		OnStop: func(_ context.Context) error { return s.Close() },
	})
	return s, nil
}

type reaperParams struct {
	fx.In

	Store  *Store
	Logger *zap.Logger `optional:"true"`

	Interval           time.Duration `name:"state_reaper_interval"`
	RefreshMaxLifetime time.Duration `name:"oidc_refresh_max_lifetime"`
}

// newReaperFx builds the expired-state reaper. It is only constructed here;
// `serve` runs it, so one-shot subcommands (migrate, keys) never sweep.
func newReaperFx(p reaperParams) (*Reaper, error) {
	if p.Interval < 0 {
		return nil, fmt.Errorf("sqlite: STATE_REAPER_INTERVAL must not be negative, got %s", p.Interval)
	}
	opts := []ReaperOption{
		WithReaperInterval(p.Interval),
		WithReaperRefreshMaxLifetime(p.RefreshMaxLifetime),
	}
	if p.Logger != nil {
		opts = append(opts, WithReaperLogger(p.Logger.Named("reaper")))
	}
	return NewReaper(p.Store, opts...), nil
}

// Fx registers the sqlite store as *Store (for direct callers like
// cmd/serve.go) plus every consumer-side interface it satisfies
// (keys.KeyStore, keys.DenylistChecker, oidc.AuthRequestStore,
// oidc.BrowserSessionStore, oidc.CallbackStore, oidc.TokenStore,
// oidc.DeviceCodeStore, api.StoreProbe), using a single underlying
// constructor.
// admin.KeyRegistry and admin.SessionStore are provided as separate adapter
// constructors (see admin_adapter.go) because their short method names
// (Save/ByID/List/MarkRevoked, List/RevokeFamily/...) deliberately differ from the prefixed
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
				fx.As(new(api.StoreProbe)),
				fx.As(fx.Self()),
			),
		),
		fx.Provide(newAdminKeyRegistry, newAdminSessionStore),
		fx.Provide(newReaperFx),
	)
}
