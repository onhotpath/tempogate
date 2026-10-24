package postgres

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/fx"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/redact"
)

type Params struct {
	fx.In

	Lifecycle fx.Lifecycle
	Logger    *zap.Logger `optional:"true"`

	DSN                  string        `name:"postgres_dsn"`
	DSNFile              string        `name:"postgres_dsn_file"`
	ListenDSN            string        `name:"postgres_listen_dsn"`
	MaxConns             int           `name:"postgres_max_conns"`
	ConnMaxIdleTime      time.Duration `name:"postgres_conn_max_idle_time"`
	AllowInsecureSSLMode bool          `name:"postgres_allow_insecure_sslmode"`

	Meter     observe.Meter  `optional:"true"`
	Tracer    observe.Tracer `optional:"true"`
	Redaction *redact.Set    `optional:"true"`
}

func newFx(p Params) (*Store, error) {
	opts := []Option{
		WithDSN(p.DSN),
		WithDSNFile(p.DSNFile),
		WithListenDSN(p.ListenDSN),
		WithMaxConns(p.MaxConns),
		WithConnMaxIdleTime(p.ConnMaxIdleTime),
		WithAllowInsecureSSLMode(p.AllowInsecureSSLMode),
		WithMeter(p.Meter),
		WithTracer(p.Tracer),
		WithRedaction(p.Redaction),
	}
	if p.Logger != nil {
		opts = append(opts, WithLogger(p.Logger.Named("postgres")))
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
		return nil, fmt.Errorf("postgres: STATE_REAPER_INTERVAL must not be negative, got %s", p.Interval)
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

// Fx registers the Postgres store the way sqlite.Fx registers SQLite's: as
// *Store plus every consumer-side interface it satisfies, keys.BootstrapLocker
// included, with the admin adapters and the reaper. state/doc.go holds the
// contract of each.
func Fx() fx.Option {
	return fx.Options(
		fx.Provide(
			fx.Annotate(
				newFx,
				fx.As(new(keys.KeyStore)),
				fx.As(new(keys.DenylistChecker)),
				fx.As(new(keys.ChangeFeed)),
				fx.As(new(keys.BootstrapLocker)),
				fx.As(new(oidc.AuthRequestStore)),
				fx.As(new(oidc.BrowserSessionStore)),
				fx.As(new(oidc.CallbackStore)),
				fx.As(new(oidc.TokenStore)),
				fx.As(new(oidc.DeviceCodeStore)),
				fx.As(new(api.StoreProbe)),
				fx.As(fx.Self()),
			),
		),
		fx.Provide(NewAdminKeyRegistry, NewAdminSessionStore),
		fx.Provide(newReaperFx),
	)
}
