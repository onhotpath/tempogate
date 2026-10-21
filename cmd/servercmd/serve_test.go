package servercmd

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/config"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/state/sqlite"
)

type ServeCmdSuite struct {
	suite.Suite

	ctx   context.Context
	store *sqlite.Store
	path  string
}

func TestServeCmdSuite(t *testing.T) {
	suite.Run(t, new(ServeCmdSuite))
}

func (s *ServeCmdSuite) SetupTest() {
	s.ctx = context.Background()
	s.path = filepath.Join(s.T().TempDir(), "state.db")

	store, err := sqlite.New(sqlite.WithPath(s.path))
	s.Require().NoError(err)
	s.store = store
}

func (s *ServeCmdSuite) TearDownTest() {
	if s.store != nil {
		s.Require().NoError(s.store.Close())
		s.store = nil
	}
}

func (s *ServeCmdSuite) TestRejectsStaleSchema() {
	cmd := newServeCmd(supply(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema version 0, expected ")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *ServeCmdSuite) TestRejectsSchemaWithGap() {
	s.Require().NoError(s.store.Migrate(s.ctx))

	// Simulate a migration merged out of numeric order: a lower version is
	// unapplied while the highest one is recorded.
	db, err := sql.Open("sqlite", s.path)
	s.Require().NoError(err)
	_, err = db.ExecContext(s.ctx, `DELETE FROM schema_migrations WHERE version = 3`)
	s.Require().NoError(err)
	s.Require().NoError(db.Close())

	cmd := newServeCmd(supply(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err = cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "schema is missing migrations 3")
	s.Contains(err.Error(), "tempogate migrate")
}

func (s *ServeCmdSuite) TestRejectsUnreachableStore() {
	s.Require().NoError(s.store.Close())

	cmd := newServeCmd(supply(serveParams{
		Logger: zap.NewNop(),
		Store:  s.store,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	err := cmd.ExecuteContext(s.ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "state store unreachable")

	s.store = nil
}

// TestAPIDocsRequireDevIssuer: the docs are for a local dev stack, so serve
// refuses to start with them on behind anything but a plain-http issuer, and
// says so before touching the store. Past the check, the unmigrated store is
// what stops serve.
func (s *ServeCmdSuite) TestAPIDocsRequireDevIssuer() {
	for _, tc := range []struct {
		name      string
		docs      bool
		plainHTTP bool
		wantErr   string
	}{
		{"docs on, https issuer", true, false, "API_DOCS_ENABLED is for local development only and requires a plain-http OIDC_ISSUER"},
		{"docs on, http issuer", true, true, "schema version 0"},
		{"docs off, https issuer", false, false, "schema version 0"},
	} {
		s.Run(tc.name, func() {
			cmd := newServeCmd(supply(serveParams{
				Logger:          zap.NewNop(),
				Store:           s.store,
				DocsEnabled:     tc.docs,
				IssuerPlainHTTP: tc.plainHTTP,
			}))
			cmd.SetOut(new(testWriter))
			cmd.SetErr(new(testWriter))

			err := cmd.ExecuteContext(s.ctx)
			s.Require().Error(err)
			s.Contains(err.Error(), tc.wantErr)
			if tc.docs && !tc.plainHTTP {
				s.Contains(err.Error(), "tempogate gen-oas", "the refusal points at the way to get the specs")
			}
		})
	}
}

// TestServesUntilCancelled drives serve's happy path: on a migrated store it
// bootstraps the signing keypair, binds both listeners, marks readiness, and
// shuts down cleanly when the command's context is cancelled.
func (s *ServeCmdSuite) TestServesUntilCancelled() {
	s.Require().NoError(s.store.Migrate(s.ctx))

	readiness := api.NewReadiness()
	loopback := config.Listener{IP: net.IPv4(127, 0, 0, 1)} // port 0: any free port
	cmd := newServeCmd(supply(serveParams{
		Logger:        zap.NewNop(),
		Store:         s.store,
		Reaper:        sqlite.NewReaper(s.store),
		Keys:          keys.New(keys.WithStore(s.store)),
		Servers:       api.New(readiness),
		Readiness:     readiness,
		Listener:      loopback,
		AdminListener: loopback,
		Server:        config.ServerConfig{ShutdownTimeout: 5 * time.Second},
		KeysReload:    time.Second,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.ExecuteContext(ctx) }()

	s.Require().Eventually(readiness.IsReady, 10*time.Second, 10*time.Millisecond)
	kps, err := s.store.LoadKeypairs(s.ctx)
	s.Require().NoError(err)
	s.Len(kps, 1, "serve must bootstrap the signing keypair before listening")

	cancel()
	select {
	case err := <-errCh:
		s.Require().NoError(err)
	case <-time.After(10 * time.Second):
		s.FailNow("serve did not stop after cancellation")
	}
}

// TestReloadsKeysWhileServing proves a keypair generated by another process
// (here: a second *keys.Keys over the same store, as `tempogate keys
// generate --force` would be) becomes the serving signer without a restart.
func (s *ServeCmdSuite) TestReloadsKeysWhileServing() {
	s.Require().NoError(s.store.Migrate(s.ctx))

	readiness := api.NewReadiness()
	// No publish delay: this test is about the reload, not the delay.
	serving := keys.New(
		keys.WithStore(s.store),
		keys.WithPublishDelay(0),
		keys.WithGenerateOptions(keys.WithRSABits(2048)),
	)
	loopback := config.Listener{IP: net.IPv4(127, 0, 0, 1)}
	cmd := newServeCmd(supply(serveParams{
		Logger:        zap.NewNop(),
		Store:         s.store,
		Reaper:        sqlite.NewReaper(s.store),
		Keys:          serving,
		Servers:       api.New(readiness),
		Readiness:     readiness,
		Listener:      loopback,
		AdminListener: loopback,
		Server:        config.ServerConfig{ShutdownTimeout: 5 * time.Second},
		KeysReload:    10 * time.Millisecond,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- cmd.ExecuteContext(ctx) }()
	s.Require().Eventually(readiness.IsReady, 10*time.Second, 10*time.Millisecond)

	rotated, err := keys.New(keys.WithStore(s.store), keys.WithGenerateOptions(keys.WithRSABits(2048))).Generate(s.ctx, true)
	s.Require().NoError(err)
	s.Require().Eventually(func() bool {
		kp, err := serving.Latest()
		return err == nil && kp.Kid == rotated.Kid
	}, 5*time.Second, 10*time.Millisecond, "serve must pick up a rotated key without a restart")

	cancel()
	select {
	case err := <-errCh:
		s.Require().NoError(err)
	case <-time.After(10 * time.Second):
		s.FailNow("serve did not stop after cancellation")
	}
}

func (s *ServeCmdSuite) TestRejectsNonPositiveReloadInterval() {
	s.Require().NoError(s.store.Migrate(s.ctx))
	readiness := api.NewReadiness()
	cmd := newServeCmd(supply(serveParams{
		Logger:    zap.NewNop(),
		Store:     s.store,
		Keys:      keys.New(keys.WithStore(s.store), keys.WithGenerateOptions(keys.WithRSABits(2048))),
		Servers:   api.New(readiness),
		Readiness: readiness,
	}))
	cmd.SetOut(new(testWriter))
	cmd.SetErr(new(testWriter))

	// The deadline only bounds a regression where serve starts anyway.
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	s.Require().Error(err)
	s.Contains(err.Error(), "KEYS_RELOAD_INTERVAL")
}
