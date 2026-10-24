package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/observe"
	"github.com/onhotpath/tempogate/observe/observetest"
	"github.com/onhotpath/tempogate/oidc"
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

func TestObserve(t *testing.T) {
	forEachServer(t, func(t *testing.T, srv testServer) {
		// Every runtime store operation reports a failure under a fixed op
		// name, so tempogate_db_errors_total can say which query is failing.
		t.Run("DBErrorsAreObservedByOp", func(t *testing.T) {
			obs := newRecordingObserver()
			st := newTestStore(t, srv, WithMeter(obs.meter), WithTracer(obs.tracer))
			st.pool.Close()

			ctx := obs.traced(t.Context())
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
				{"list_refresh_sessions", func() error { _, err := st.ListRefreshSessions(ctx, admin.SessionFilter{}, now); return err }},
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
				{"mark_integration_key_revoked", func() error { _, err := st.MarkIntegrationKeyRevoked(ctx, "x", now); return err }},
				{"is_current", func() error { return st.IsCurrent(ctx) }},
				{"probe", func() error { return st.Probe(ctx) }},
				{"lock_key_bootstrap", func() error {
					return st.LockKeyBootstrap(ctx, func(context.Context) error { return nil })
				}},
			}
			want := make([]string, 0, len(calls))
			for _, c := range calls {
				require.Error(t, c.fn(), c.op)
				want = append(want, c.op)
			}
			require.Equal(t, want, obs.calls())
			// Each call is one operation, begun and ended once.
			started, ended := obs.starts()
			require.Equal(t, want, started)
			require.True(t, ended, "every operation ends")
		})

		// A miss is a normal protocol outcome (replayed code, unknown
		// token), not a database failure, and must not inflate the counter.
		t.Run("NotFoundIsNotADBError", func(t *testing.T) {
			obs := newRecordingObserver()
			st := newTestStore(t, srv, WithMeter(obs.meter), WithTracer(obs.tracer))
			ctx := obs.traced(t.Context())

			_, err := st.ConsumeRefresh(ctx, "never-issued", "ui", time.Now())
			require.ErrorIs(t, err, oidc.ErrRefreshNotFound)
			_, err = st.ConsumeAuthCode(ctx, "never-issued", "family", time.Now())
			require.ErrorIs(t, err, oidc.ErrAuthCodeNotFound)
			_, err = st.RevokeRefreshFamily(ctx, "never-issued", time.Now())
			require.ErrorIs(t, err, admin.ErrSessionNotFound)
			require.Error(t, st.UpdateKeypairPrivatePEM(ctx, "no-such-kid", nil))
			require.NoError(t, st.Probe(ctx))
			require.Empty(t, obs.calls())
			started, ended := obs.starts()
			require.Equal(t, []string{"consume_refresh", "consume_auth_code", "revoke_refresh", "update_keypair_private_pem", "probe"}, started)
			require.True(t, ended, "a miss still ends its operation")
		})

		t.Run("DuplicatesAreTheirSentinels", func(t *testing.T) {
			st := newTestStore(t, srv)
			ctx := t.Context()
			at := time.Now().UTC()
			require.NoError(t, st.SaveAuthRequest(ctx, oidc.AuthRequest{InternalState: "s", CreatedAt: at, ExpiresAt: at}))
			require.ErrorIs(t, st.SaveAuthRequest(ctx, oidc.AuthRequest{InternalState: "s", CreatedAt: at, ExpiresAt: at}), ErrDuplicateInternalState)
			require.NoError(t, st.SaveAuthCode(ctx, oidc.AuthCode{Code: "c", CreatedAt: at, ExpiresAt: at}))
			require.ErrorIs(t, st.SaveAuthCode(ctx, oidc.AuthCode{Code: "c", CreatedAt: at, ExpiresAt: at}), ErrDuplicateAuthCode)
			require.NoError(t, st.SaveBrowserSession(ctx, oidc.BrowserSession{SID: "b", CreatedAt: at, ExpiresAt: at}))
			require.ErrorIs(t, st.SaveBrowserSession(ctx, oidc.BrowserSession{SID: "b", CreatedAt: at, ExpiresAt: at}), ErrDuplicateBrowserSession)
			r := oidc.Refresh{Token: "r", FamilyID: "f", AuthTime: at, CreatedAt: at, ExpiresAt: at}
			require.NoError(t, st.SaveRefresh(ctx, r))
			require.ErrorIs(t, st.SaveRefresh(ctx, r), ErrDuplicateRefreshToken)
			kp := keys.Keypair{Kid: "k", Alg: "RS256", PrivatePEM: []byte("p"), PublicPEM: []byte("p"), CreatedAt: at}
			require.NoError(t, st.SaveKeypair(ctx, kp))
			require.ErrorIs(t, st.SaveKeypair(ctx, kp), ErrDuplicateKid)
		})
	})
}
