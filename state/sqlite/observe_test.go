package sqlite

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/oidc"
	"github.com/onhotpath/tempogate/state/internal/instrument"
)

// recordingObserver reads back what a store recorded: calls are the operations
// counted as failed, in order; starts are the operations traced, so one left
// open or nested in another shows.
type recordingObserver struct {
	meter  *observetest.Meter
	tracer *observetest.Tracer
}

func newRecordingObserver() *recordingObserver {
	return &recordingObserver{meter: observetest.NewMeter(), tracer: observetest.NewTracer()}
}

// calls is the op label of every failure counted, in order.
func (r *recordingObserver) calls() []string {
	var ops []string
	for _, m := range r.meter.Measurements("tempogate.db_errors") {
		ops = append(ops, m.Attrs["op"])
	}
	return ops
}

// traced returns ctx inside a request's span, so the store operations run
// under it are traced.
func (r *recordingObserver) traced(ctx context.Context) context.Context {
	ctx, _ = r.tracer.Start(ctx, "request", observe.AsRoot())
	return ctx
}

// starts returns the operations traced so far, and whether each has ended.
func (r *recordingObserver) starts() ([]string, bool) {
	var (
		ops   []string
		ended = true
	)
	for _, sp := range r.tracer.Spans() {
		op, ok := strings.CutPrefix(sp.Name, "store ")
		if !ok {
			continue
		}
		ops = append(ops, op)
		ended = ended && sp.Ended && sp.Parent != nil && sp.Parent.Name == "request"
	}
	return ops, ended
}

// observedStore is a migrated store wired to a fresh recording observer.
func (s *StoreSuite) observedStore() (*Store, *recordingObserver, string) {
	obs := newRecordingObserver()
	path := filepath.Join(s.T().TempDir(), "observed.db")
	st, err := New(WithPath(path), WithBusyTimeout(time.Second), WithMeter(obs.meter), WithTracer(obs.tracer))
	s.Require().NoError(err)
	s.Require().NoError(st.Migrate(s.ctx))
	s.T().Cleanup(func() { _ = st.Close() })
	return st, obs, path
}

// Every runtime store operation reports a failure under a fixed op name, so
// tempogate_db_errors_total can say which query is failing.
func (s *StoreSuite) TestDBErrorsAreObservedByOp() {
	st, obs, _ := s.observedStore()
	s.Require().NoError(st.Close())

	ctx := obs.traced(s.ctx)
	now := time.Now()
	calls := []struct {
		op string
		fn func() error
	}{
		{"save_auth_request", func() error { return st.SaveAuthRequest(ctx, oidc.AuthRequest{}) }},
		{"consume_auth_request", func() error { _, err := st.ConsumeAuthRequest(ctx, "x"); return err }},
		{"save_auth_code", func() error { return st.SaveAuthCode(ctx, oidc.AuthCode{}) }},
		{"consume_auth_code", func() error { _, err := st.ConsumeAuthCode(ctx, "x", "family", now); return err }},
		{"save_refresh", func() error { return st.SaveRefresh(ctx, oidc.Refresh{}) }},
		{"consume_refresh", func() error { _, err := st.ConsumeRefresh(ctx, "x", "ui", now); return err }},
		{"revoke_refresh", func() error { _, err := st.RevokeRefreshFamily(ctx, "family", now); return err }},
		{"revoke_refresh", func() error { _, err := st.RevokeRefreshByEmail(ctx, "a@example.com", now); return err }},
		{"revoke_refresh", func() error { _, err := st.RevokeRefreshBySubject(ctx, "google", "sub", now); return err }},
		{"list_refresh_sessions", func() error { _, err := st.ListRefreshSessions(ctx, RefreshSessionFilter{}, now); return err }},
		{"save_browser_session", func() error { return st.SaveBrowserSession(ctx, oidc.BrowserSession{}) }},
		{"lookup_browser_session", func() error { _, err := st.LookupBrowserSession(ctx, "x"); return err }},
		{"delete_browser_session", func() error { return st.DeleteBrowserSession(ctx, "x") }},
		{"save_device_code", func() error { return st.SaveDeviceCode(ctx, oidc.DeviceCode{}) }},
		{"lookup_device_code", func() error { _, err := st.LookupDeviceCodeByDeviceCode(ctx, "x"); return err }},
		{"lookup_device_code", func() error { _, err := st.LookupDeviceCodeByUserCode(ctx, "x"); return err }},
		{"poll_device_code", func() error { _, err := st.PollDeviceCode(ctx, "x", now); return err }},
		{"decide_device_code", func() error {
			return st.ApproveDeviceCode(ctx, "x", oidc.Identity{Subject: "s", Email: "a@example.com"}, now)
		}},
		{"decide_device_code", func() error { return st.DenyDeviceCode(ctx, "x", now) }},
		{"consume_device_code", func() error { _, err := st.ConsumeDeviceCode(ctx, "x"); return err }},
		{"save_keypair", func() error { return st.SaveKeypair(ctx, keys.Keypair{}) }},
		{"load_keypairs", func() error { _, err := st.LoadKeypairs(ctx); return err }},
		{"update_keypair_private_pem", func() error { return st.UpdateKeypairPrivatePEM(ctx, "kid", nil) }},
		{"retire_keypair", func() error { _, err := st.RetireKeypair(ctx, "kid", now); return err }},
		{"is_revoked", func() error { _, err := st.IsRevoked(ctx, "x"); return err }},
		{"save_integration_key", func() error { return st.SaveIntegrationKey(ctx, admin.IntegrationKey{}) }},
		{"integration_key_by_id", func() error { _, err := st.IntegrationKeyByID(ctx, "x"); return err }},
		{"list_integration_keys", func() error { _, err := st.ListIntegrationKeys(ctx, admin.ListFilter{}); return err }},
		{"mark_integration_key_revoked", func() error { _, err := st.MarkIntegrationKeyRevoked(ctx, "x", time.Now().UTC()); return err }},
		{"is_current", func() error { return st.IsCurrent(ctx) }},
	}
	want := make([]string, 0, len(calls))
	for _, c := range calls {
		s.Require().Error(c.fn(), c.op)
		want = append(want, c.op)
	}
	s.Equal(want, obs.calls())
	// Each call is one operation, begun and ended once: a helper shared by
	// several methods must not nest a second one.
	started, ended := obs.starts()
	s.Equal(want, started)
	s.True(ended, "every operation ends")
}

// A miss is a normal protocol outcome (replayed code, unknown token), not a
// database failure, and must not inflate the error counter.
func (s *StoreSuite) TestNotFoundIsNotADBError() {
	st, obs, _ := s.observedStore()
	ctx := obs.traced(s.ctx)

	_, err := st.ConsumeRefresh(ctx, "never-issued", "ui", time.Now())
	s.Require().ErrorIs(err, oidc.ErrRefreshNotFound)
	_, err = st.ConsumeAuthCode(ctx, "never-issued", "family", time.Now())
	s.Require().ErrorIs(err, oidc.ErrAuthCodeNotFound)

	s.Empty(obs.calls())
	started, ended := obs.starts()
	s.Equal([]string{"consume_refresh", "consume_auth_code"}, started)
	s.True(ended, "a miss still ends its operation")
}

func (s *StoreSuite) TestProbeHealthy() {
	st, obs, _ := s.observedStore()

	s.Require().NoError(st.Probe(obs.traced(s.ctx)))
	s.Empty(obs.calls())
	started, ended := obs.starts()
	s.Equal([]string{"probe"}, started, "a successful operation is traced too")
	s.True(ended)
}

// The serving connection keeps an open descriptor, so it happily reads and
// writes a database file that has been deleted or replaced underneath it.
// Probe must look at the file the path names now.
func (s *StoreSuite) TestProbeFailsWhenTheFileIsGone() {
	cases := map[string]func(path string){
		"file removed": func(path string) {
			for _, suffix := range []string{"", "-wal", "-shm"} {
				s.Require().NoError(os.RemoveAll(path + suffix))
			}
		},
		"directory removed": func(path string) { s.Require().NoError(os.RemoveAll(filepath.Dir(path))) },
		"file truncated":    func(path string) { s.Require().NoError(os.Truncate(path, 0)) },
	}
	for name, breakIt := range cases {
		s.Run(name, func() {
			st, obs, path := s.observedStore()
			s.Require().NoError(st.Probe(s.ctx))

			breakIt(path)

			s.Require().Error(st.Probe(s.ctx))
			s.Equal([]string{"probe"}, obs.calls())
		})
	}
}

func (s *StoreSuite) TestProbeFailsWhenClosed() {
	st, _, _ := s.observedStore()
	s.Require().NoError(st.Close())

	s.Require().Error(st.Probe(s.ctx))
}

func (s *StoreSuite) TestProbeHonoursContext() {
	st, _, _ := s.observedStore()
	ctx, cancel := context.WithCancel(s.ctx)
	cancel()

	s.Require().Error(st.Probe(ctx))
}

// observeSuiteStore attaches a fresh recording observer to the suite's own
// migrated store, so the suite's seed helpers can set up rows first.
func (s *StoreSuite) observeSuiteStore() *recordingObserver {
	obs := newRecordingObserver()
	ops, err := instrument.New(obs.meter, obs.tracer)
	s.Require().NoError(err)
	s.store.ops = ops
	return obs
}

// failWrites makes every write of kind (INSERT, UPDATE) on table abort, the
// way a full disk or a corrupt page fails one statement while earlier ones in
// the same operation succeeded.
func (s *StoreSuite) failWrites(kind, table string) {
	_, err := s.store.db.ExecContext(s.ctx, fmt.Sprintf(
		`CREATE TRIGGER fail_%[1]s_%[2]s BEFORE %[1]s ON %[2]s BEGIN SELECT RAISE(ABORT, 'injected failure'); END`,
		kind, table))
	s.Require().NoError(err)
}

// corrupt overwrites a column with a value the store cannot scan back, the
// shape of a row damaged on disk or by a hand edit.
func (s *StoreSuite) corrupt(table, column string) {
	_, err := s.store.db.ExecContext(s.ctx, fmt.Sprintf(`UPDATE %s SET %s = 'not-a-time'`, table, column))
	s.Require().NoError(err)
}

// failCommit makes every transaction that inserts into table fail at COMMIT,
// after all its statements succeeded, through a deferred foreign key that is
// never satisfied.
func (s *StoreSuite) failCommit(table string) {
	_, err := s.store.db.ExecContext(s.ctx, fmt.Sprintf(`
		CREATE TABLE commit_guard_parent (id INTEGER PRIMARY KEY);
		CREATE TABLE commit_guard (parent INTEGER REFERENCES commit_guard_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_commit_%[1]s AFTER INSERT ON %[1]s BEGIN INSERT INTO commit_guard VALUES (1); END`,
		table))
	s.Require().NoError(err)
}

// A revoke whose denylist write or commit fails is counted and rolls back as
// a whole: the key must not read as revoked while its jti still verifies.
func (s *StoreSuite) TestRevokeFailingMidTransactionIsObservedAndRolledBack() {
	for _, tc := range []struct {
		name, err string
		inject    func()
	}{
		{"UPDATE integration_keys", "injected failure", func() { s.failWrites("UPDATE", "integration_keys") }},
		{"INSERT jti_denylist", "injected failure", func() { s.failWrites("INSERT", "jti_denylist") }},
		{"COMMIT", "sqlite: commit mark revoked: ", func() { s.failCommit("jti_denylist") }},
	} {
		s.Run(tc.name, func() {
			s.TearDownTest()
			s.SetupTest()
			k := s.seedKey(admin.WithNamespace("default"), admin.WithRole(admin.RoleRead), admin.WithOwner("ops"))
			obs := s.observeSuiteStore()
			tc.inject()

			_, err := s.store.MarkIntegrationKeyRevoked(s.ctx, k.ID, time.Now().UTC())
			s.Require().ErrorContains(err, tc.err)
			s.Equal([]string{"mark_integration_key_revoked"}, obs.calls())

			got, err := s.store.IntegrationKeyByID(s.ctx, k.ID)
			s.Require().NoError(err)
			s.Nil(got.RevokedAt, "a failed revoke must leave the key active")
			revoked, err := s.store.IsRevoked(s.ctx, k.JTI)
			s.Require().NoError(err)
			s.False(revoked, "a failed revoke must leave the jti off the denylist")
		})
	}
}

// Device-flow writes that fail after their read succeeded are counted under
// the operation, on both the poll stamp and the slow_down path, and on a
// decision.
func (s *StoreSuite) TestDeviceCodeWriteFailuresAreObserved() {
	now := time.Now().UTC()
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, s.deviceCode("dc-stamp", "BCDF-GHJK")))
	s.Require().NoError(s.store.SaveDeviceCode(s.ctx, s.deviceCode("dc-slow", "CDFG-HJKL")))
	_, err := s.store.PollDeviceCode(s.ctx, "dc-slow", now)
	s.Require().NoError(err)
	obs := s.observeSuiteStore()
	s.failWrites("UPDATE", "device_codes")

	_, err = s.store.PollDeviceCode(s.ctx, "dc-stamp", now)
	s.Require().ErrorContains(err, "injected failure", "first poll: the stamp fails")
	_, err = s.store.PollDeviceCode(s.ctx, "dc-slow", now)
	s.Require().ErrorContains(err, "slow_down", "a poll inside the interval: the slow_down write fails")
	err = s.store.ApproveDeviceCode(s.ctx, "BCDF-GHJK", oidc.Identity{Subject: "s", Email: "a@example.com"}, now)
	s.Require().ErrorContains(err, "injected failure")

	s.Equal([]string{"poll_device_code", "poll_device_code", "decide_device_code"}, obs.calls())
}

// A replayed code or token whose tombstone cannot be read back is a database
// failure, not a clean "reused" verdict, and is counted as one.
func (s *StoreSuite) TestUnreadableTombstonesAreObserved() {
	now := time.Now().UTC()
	ac := oidc.AuthCode{
		Code: "code-1", ClientID: "ui", RedirectURI: "http://127.0.0.1/cb", Subject: "sub", Email: "a@example.com",
		CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	s.Require().NoError(s.store.SaveAuthCode(s.ctx, ac))
	_, err := s.store.ConsumeAuthCode(s.ctx, "code-1", "family-1", now)
	s.Require().NoError(err)
	rt := oidc.Refresh{
		Token: "rt-1", JTI: "jti-1", ClientID: "ui", Subject: "sub", Email: "a@example.com",
		FamilyID: "family-1", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	s.Require().NoError(s.store.SaveRefresh(s.ctx, rt))
	_, err = s.store.ConsumeRefresh(s.ctx, "rt-1", "ui", now)
	s.Require().NoError(err)
	obs := s.observeSuiteStore()
	s.corrupt("auth_codes", "created_at")
	s.corrupt("refresh_tokens", "created_at")

	_, err = s.store.ConsumeAuthCode(s.ctx, "code-1", "family-2", now)
	s.Require().Error(err)
	s.NotErrorIs(err, oidc.ErrAuthCodeReused)
	_, err = s.store.ConsumeRefresh(s.ctx, "rt-1", "ui", now)
	s.Require().Error(err)
	s.NotErrorIs(err, oidc.ErrRefreshReused)

	s.Equal([]string{"consume_auth_code", "consume_refresh"}, obs.calls())
}

// Listings that hit an unreadable row fail (and are counted) instead of
// silently dropping it.
func (s *StoreSuite) TestUnreadableListingsAreObserved() {
	now := time.Now().UTC()
	s.seedKey(admin.WithNamespace("default"), admin.WithRole(admin.RoleRead), admin.WithOwner("ops"))
	s.Require().NoError(s.store.SaveRefresh(s.ctx, oidc.Refresh{
		Token: "rt-1", JTI: "jti-1", ClientID: "ui", Subject: "sub", Email: "a@example.com",
		FamilyID: "family-1", AuthTime: now, CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}))
	obs := s.observeSuiteStore()
	s.corrupt("integration_keys", "created_at")
	s.corrupt("refresh_tokens", "auth_time")

	_, err := s.store.ListIntegrationKeys(s.ctx, admin.ListFilter{})
	s.Require().Error(err)
	_, err = s.store.ListRefreshSessions(s.ctx, RefreshSessionFilter{}, now)
	s.Require().Error(err)

	s.Equal([]string{"list_integration_keys", "list_refresh_sessions"}, obs.calls())
}

// A schema_migrations that cannot be read fails the version check as a
// database error, not as a database short of its migrations.
func (s *StoreSuite) TestUnreadableSchemaVersionIsObserved() {
	obs := s.observeSuiteStore()
	// abs() of the smallest int64 overflows, so every read of the view fails.
	_, err := s.store.db.ExecContext(s.ctx, `
		DROP TABLE schema_migrations;
		CREATE VIEW schema_migrations AS SELECT abs(-9223372036854775807 - 1) AS version`)
	s.Require().NoError(err)

	s.Require().ErrorContains(s.store.IsCurrent(s.ctx), "sqlite: read schema_migrations: ")
	s.Equal([]string{"is_current"}, obs.calls())
}
