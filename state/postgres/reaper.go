package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/internal/clock"
)

const (
	defaultReapInterval  = 5 * time.Minute
	defaultReapBatchSize = 500

	// denylistGrace keeps a revoked integration key's jti denylisted for a
	// while past the token's exp, so a verifier whose clock runs behind
	// still refuses it.
	denylistGrace = time.Hour
)

// expiringTables hold rows that are dead once expires_at passes, keyed by
// their primary key: every reader already refuses an expired row, so
// deleting it changes no answer.
var expiringTables = []struct{ table, key string }{
	{"auth_requests", "internal_state"},
	{"auth_codes", "code_hash"},
	{"device_codes", "device_code_hash"},
	{"browser_sessions", "sid_hash"},
}

// Reaper deletes expired state, a batch per statement. Every batch picks its
// rows FOR UPDATE SKIP LOCKED, so the reapers of several replicas share the
// work instead of queueing on each other, and none waits on a row a request
// is using: a skipped row is reaped on a later sweep. No leader election is
// needed.
type Reaper struct {
	store              *Store
	interval           time.Duration
	refreshMaxLifetime time.Duration
	batch              int
	now                func() time.Time
	logger             *zap.Logger
}

type ReaperOption func(*Reaper)

// WithReaperInterval sets how often Run sweeps; 0 disables it.
func WithReaperInterval(d time.Duration) ReaperOption {
	return func(r *Reaper) { r.interval = d }
}

// WithReaperRefreshMaxLifetime is OIDC_REFRESH_MAX_LIFETIME: a refresh
// family is dead once its sign-in is this old. 0 keeps families until
// every row has expired and been consumed or revoked.
func WithReaperRefreshMaxLifetime(d time.Duration) ReaperOption {
	return func(r *Reaper) { r.refreshMaxLifetime = d }
}

// WithReaperBatchSize sets how many rows (refresh families, for refresh
// tokens) one statement deletes. Non-positive keeps the default.
func WithReaperBatchSize(n int) ReaperOption {
	return func(r *Reaper) {
		if n > 0 {
			r.batch = n
		}
	}
}

// WithReaperClock swaps the clock. For tests.
func WithReaperClock(now func() time.Time) ReaperOption {
	return func(r *Reaper) { r.now = now }
}

func WithReaperLogger(l *zap.Logger) ReaperOption {
	return func(r *Reaper) { r.logger = l }
}

func NewReaper(store *Store, opts ...ReaperOption) *Reaper {
	r := &Reaper{
		store:    store,
		interval: defaultReapInterval,
		batch:    defaultReapBatchSize,
		now:      clock.Now,
		logger:   zap.NewNop(),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Run sweeps once at start, then every interval, until ctx is cancelled.
// A failed sweep is logged and retried on the next tick: the server keeps
// serving either way.
func (r *Reaper) Run(ctx context.Context) error {
	if r.interval <= 0 {
		return nil
	}
	t := time.NewTicker(r.interval)
	defer t.Stop()
	for {
		r.sweep(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

func (r *Reaper) sweep(ctx context.Context) {
	counts, err := r.Reap(ctx)
	if ctx.Err() != nil {
		return // shutting down; the interrupted batch is retried next start
	}
	if err != nil {
		_ = r.store.ops.Fail(ctx, "reap", err)
		r.logger.Warn("reaping expired state failed", zap.Error(err))
	}
	fields := make([]zap.Field, 0, len(counts))
	for table, n := range counts {
		fields = append(fields, zap.Int(table, n))
	}
	r.logger.Debug("reaped expired state", fields...)
}

// Reap runs one sweep and reports the rows deleted per table. A failure on
// one table does not stop the others.
func (r *Reaper) Reap(ctx context.Context) (map[string]int, error) {
	now := r.now()
	counts := map[string]int{}
	var errs []error
	for _, t := range expiringTables {
		// #nosec G202 -- table and key are the constants in expiringTables.
		n, err := r.batches(ctx,
			`DELETE FROM `+t.table+` WHERE `+t.key+` IN (
			     SELECT `+t.key+` FROM `+t.table+` WHERE expires_at < $1
			     LIMIT $2 FOR UPDATE SKIP LOCKED
			 )`,
			now)
		counts[t.table] = n
		if err != nil {
			errs = append(errs, fmt.Errorf("postgres: reap %s: %w", t.table, err))
		}
	}

	n, err := r.reapRefreshFamilies(ctx, now)
	counts["refresh_tokens"] = n
	if err != nil {
		errs = append(errs, fmt.Errorf("postgres: reap refresh_tokens: %w", err))
	}

	n, err = r.batches(ctx,
		`DELETE FROM jti_denylist WHERE jti IN (
		     SELECT d.jti FROM jti_denylist d JOIN integration_keys k ON k.jti = d.jti
		     WHERE k.expires_at < $1
		     LIMIT $2 FOR UPDATE OF d SKIP LOCKED
		 )`,
		now.Add(-denylistGrace))
	counts["jti_denylist"] = n
	if err != nil {
		errs = append(errs, fmt.Errorf("postgres: reap jti_denylist: %w", err))
	}
	return counts, errors.Join(errs...)
}

// reapRefreshFamilies deletes whole families, never single rows, for the
// reason state/sqlite/reaper.go gives: a consumed token is the tombstone
// that recognises a replay, so a family goes only when every row is dead,
// because its sign-in is past OIDC_REFRESH_MAX_LIFETIME or the row expired
// and was consumed or revoked. Nothing can be added to such a family
// (rotation needs a live row), and a family a rotation holds FOR SHARE is
// skipped. Its refresh_families row goes with it. The count is tokens.
func (r *Reaper) reapRefreshFamilies(ctx context.Context, now time.Time) (int, error) {
	var ended *time.Time // sign-ins at or before this are past the absolute lifetime
	if r.refreshMaxLifetime > 0 {
		t := now.Add(-r.refreshMaxLifetime)
		ended = &t
	}
	return r.batches(ctx,
		`WITH dead AS (
		     SELECT f.family_id FROM refresh_families f
		     WHERE NOT EXISTS (
		         SELECT 1 FROM refresh_tokens t
		         WHERE t.family_id = f.family_id
		           AND NOT (coalesce(t.auth_time <= $3, false)
		                    OR ((t.consumed_at IS NOT NULL OR t.revoked_at IS NOT NULL) AND t.expires_at < $1))
		     )
		     LIMIT $2 FOR UPDATE OF f SKIP LOCKED
		 ), families AS (
		     DELETE FROM refresh_families f USING dead WHERE f.family_id = dead.family_id
		 )
		 DELETE FROM refresh_tokens t USING dead WHERE t.family_id = dead.family_id`,
		now, ended)
}

// batches runs stmt, which takes $1 and a batch size $2 (and any further
// args), until it deletes fewer than a batch, and reports the rows deleted.
// Each run is its own statement, so locks are held only one batch long.
func (r *Reaper) batches(ctx context.Context, stmt string, arg any, more ...any) (int, error) {
	args := append([]any{arg, r.batch}, more...)
	deleted := 0
	for {
		tag, err := r.store.pool.Exec(ctx, stmt, args...)
		if err != nil {
			return deleted, err
		}
		n := int(tag.RowsAffected())
		deleted += n
		if n < r.batch {
			return deleted, nil
		}
	}
}
