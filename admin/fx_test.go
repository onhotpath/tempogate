package admin_test

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/stretchr/testify/suite"
	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

// FxSuite exercises admin.Fx() end-to-end: the graph must produce a registrar
// into the api package's `admin_registrars` group, and that registrar must
// build over the sqlite-backed admin.KeyRegistry (via the shim adapter) plus
// a Signer. This is what catches a future refactor that accidentally points
// admin.Fx() at the wrong group (admin vs api), since the assertion below
// reads from `admin_registrars` by name — wiring it into `api_registrars`
// would also leak the /admin/keys handler onto the public listener.
type FxSuite struct {
	suite.Suite
}

func TestFxSuite(t *testing.T) {
	suite.Run(t, new(FxSuite))
}

// adminConfig supplies the named admin.* projections config.Fx provides.
func adminConfig(tokenSHA256 string) fx.Option {
	return fx.Options(
		fx.Supply(
			fx.Annotate(tokenSHA256, fx.ResultTags(`name:"admin_token_sha256"`)),
			fx.Annotate([]string{"localhost:8081"}, fx.ResultTags(`name:"admin_allowed_hosts"`)),
			fx.Annotate(false, fx.ResultTags(`name:"admin_allow_system_grants"`)),
			fx.Annotate(admin.DefaultMaxTTL, fx.ResultTags(`name:"admin_keys_max_ttl"`)),
		),
		fx.Supply(zap.NewNop()),
	)
}

func (s *FxSuite) TestFxWarnsWhenAdminAPIIsLocked() {
	core, logs := observer.New(zapcore.WarnLevel)
	var installers struct {
		fx.In
		Middlewares []func(huma.API) `group:"admin_middlewares"`
	}
	fxtest.New(s.T(),
		fx.Supply(
			fx.Annotate("", fx.ResultTags(`name:"admin_token_sha256"`)),
			fx.Annotate([]string{"localhost:8081"}, fx.ResultTags(`name:"admin_allowed_hosts"`)),
		),
		fx.Supply(zap.New(core)),
		// Only the guard is populated, so fx never builds the keys
		// registrar and its store/signer deps can stay out of this graph.
		admin.Fx(),
		fx.Populate(&installers),
	).RequireStart().RequireStop()
	s.Require().Len(installers.Middlewares, 1)
	s.Len(logs.FilterMessageSnippet("admin API is locked").All(), 1)
}

func (s *FxSuite) TestFxRejectsMalformedTokenDigest() {
	app := fx.New(
		fx.NopLogger,
		adminConfig("not-a-digest"),
		admin.Fx(),
		fx.Invoke(fx.Annotate(func([]func(huma.API)) {}, fx.ParamTags(`group:"admin_middlewares"`))),
	)
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "ADMIN_TOKEN_SHA256")
}

func (s *FxSuite) TestFxProducesAdminRegistrar() {
	var collected struct {
		fx.In
		AdminRegistrars  []func(huma.API) `group:"admin_registrars"`
		AdminMiddlewares []func(huma.API) `group:"admin_middlewares"`
	}

	dbPath := filepath.Join(s.T().TempDir(), "fx.db")

	app := fxtest.New(s.T(),
		adminConfig(digestHex(guardToken)),
		fx.Provide(func() (*sqlite.Store, error) {
			return sqlite.New(sqlite.WithPath(dbPath), sqlite.WithBusyTimeout(time.Second))
		}),
		fx.Provide(func() (*keys.Keys, error) {
			ks := &fxFakeKeyStore{}
			k := keys.New(keys.WithStore(ks), keys.WithGenerateOptions(keys.WithRSABits(2048)))
			if err := k.Init(context.Background()); err != nil {
				return nil, err
			}
			return k, nil
		}),
		fx.Provide(func(k *keys.Keys) *keys.Signer { return keys.NewSigner(keys.WithKeys(k)) }),
		// admin's DELETE handler hydrates the verifier-side denylist cache
		// after a successful revoke. The fx graph composes against the
		// concrete *keys.DenylistCache; production wiring builds one over
		// state/sqlite.Store, but this graph only proves wiring so a
		// no-op checker is enough.
		fx.Provide(func() *keys.DenylistCache { return keys.NewDenylistCache() }),
		// admin depends on admin.KeyRegistry; provide the sqlite adapter
		// the same way state/sqlite/fx.go does.
		fx.Provide(sqliteAdminAdapter),
		fx.Provide(func(s *sqlite.Store) admin.SessionStore { return &storeSessions{s: s} }),
		admin.Fx(),
		fx.Populate(&collected),
	)
	app.RequireStart().RequireStop()

	s.Require().Len(collected.AdminRegistrars, 3,
		"admin.Fx() must contribute the integration-key, signing-key and session registrars to admin_registrars")
	s.Require().Len(collected.AdminMiddlewares, 1,
		"admin.Fx() must contribute the guard to admin_middlewares")

	// Bind the produced registrar to a real Huma adapter so a future
	// rename of admin.KeysPath surfaces here at the assertion step.
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "0.0.0"))
	for _, register := range collected.AdminRegistrars {
		register(api)
	}
	s.NotNil(api.OpenAPI().Paths[admin.KeysPath])
	s.NotNil(api.OpenAPI().Paths[admin.SigningKeysPath])
	s.NotNil(api.OpenAPI().Paths[admin.SigningKeyRetirePath])
	s.NotNil(api.OpenAPI().Paths[admin.SessionsPath])
	s.NotNil(api.OpenAPI().Paths[admin.SessionsRevokePath])
}

func (s *FxSuite) TestFxRejectsNonPositiveMaxTTL() {
	app := fx.New(
		fx.NopLogger,
		fx.Supply(
			fx.Annotate([]string{"localhost:8081"}, fx.ResultTags(`name:"admin_allowed_hosts"`)),
			fx.Annotate(false, fx.ResultTags(`name:"admin_allow_system_grants"`)),
			fx.Annotate(time.Duration(0), fx.ResultTags(`name:"admin_keys_max_ttl"`)),
		),
		fx.Supply(zap.NewNop()),
		fx.Provide(func() admin.KeyRegistry { return newMemRegistry(time.Now) }),
		fx.Provide(func() *keys.Keys { return keys.New(keys.WithStore(&fxFakeKeyStore{})) }),
		fx.Provide(func(k *keys.Keys) *keys.Signer { return keys.NewSigner(keys.WithKeys(k)) }),
		fx.Provide(func() *keys.DenylistCache { return keys.NewDenylistCache() }),
		admin.Fx(),
		fx.Invoke(fx.Annotate(func([]func(huma.API)) {}, fx.ParamTags(`group:"admin_registrars"`))),
	)
	s.Require().Error(app.Err())
	s.Contains(app.Err().Error(), "ADMIN_KEYS_MAX_TTL")
}

// fxFakeKeyStore is the minimal keys.KeyStore needed to bootstrap *keys.Keys
// inside the fx test. Mirrors the helper in keys_test.go (different package).
type fxFakeKeyStore struct {
	kps []keys.Keypair
}

func (f *fxFakeKeyStore) SaveKeypair(_ context.Context, kp keys.Keypair) error {
	f.kps = append(f.kps, kp)
	return nil
}

func (f *fxFakeKeyStore) LoadKeypairs(_ context.Context) ([]keys.Keypair, error) {
	out := make([]keys.Keypair, len(f.kps))
	copy(out, f.kps)
	return out, nil
}

func (f *fxFakeKeyStore) RetireKeypair(context.Context, string, time.Time) (keys.Keypair, error) {
	return keys.Keypair{}, keys.ErrKeypairNotFound
}

// sqliteAdminAdapter mirrors what state/sqlite's production adapter does —
// reused from keys_integration_test.go via the storeRegistry helper. The fx
// test does not exercise the sqlite migration; it only needs a registry that
// satisfies admin.KeyRegistry to let the graph compose.
func sqliteAdminAdapter(s *sqlite.Store) admin.KeyRegistry {
	return &storeRegistry{s: s}
}
