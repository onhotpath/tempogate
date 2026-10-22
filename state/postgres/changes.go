package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"go.uber.org/zap"

	"github.com/onhotpath/tempogate/internal/clock"
	"github.com/onhotpath/tempogate/keys"
)

// changeChannel is the LISTEN/NOTIFY channel every replica's feed listens
// on. Payloads are "keys" or "jti:<jti>" (see encodeChange).
const changeChannel = "tempogate_changes"

const (
	// feedPing is how long the listener waits for a notification before it
	// pings, so a connection that died silently is noticed and replaced.
	feedPing = time.Minute

	// feedRetryMin and feedRetryMax bound the backoff between reconnects.
	feedRetryMin = time.Second
	feedRetryMax = 30 * time.Second

	// resyncSkew widens the window a resync re-reads revocations from: the
	// revoked_at stamps come from other replicas' clocks.
	resyncSkew = time.Minute
)

// feedApplicationName tells the LISTEN connection apart in pg_stat_activity
// unless the DSN names the application itself.
const feedApplicationName = "tempogate change feed"

// notify queues c on tx. Postgres delivers it to every listener only if tx
// commits, so a change is never reported for a write that rolled back. It
// is used only for rare writes (keypairs, integration-key revocation): a
// committing NOTIFY takes a database-wide lock, which the token path must
// never queue behind.
func notify(ctx context.Context, tx pgx.Tx, c keys.Change) error {
	_, err := tx.Exec(ctx, `SELECT pg_notify($1, $2)`, changeChannel, encodeChange(c))
	return err
}

func encodeChange(c keys.Change) string {
	if c.Kind == keys.ChangeJTIRevoked {
		return "jti:" + c.JTI
	}
	return "keys"
}

func decodeChange(payload string) (keys.Change, bool) {
	if jti, ok := strings.CutPrefix(payload, "jti:"); ok && jti != "" {
		return keys.Change{Kind: keys.ChangeJTIRevoked, JTI: jti}, true
	}
	if payload == "keys" {
		return keys.Change{Kind: keys.ChangeKeys}, true
	}
	return keys.Change{}, false
}

// SubscribeChanges satisfies keys.ChangeFeed over LISTEN/NOTIFY, so a key
// generated or retired and an integration key revoked on any replica (or by
// the CLI) reaches every replica's subscribers. The first call starts the
// store's one listening connection and returns once it is listening (or
// failed its first attempt), so a change committed after it returns is
// reported.
//
// The listener reconnects with backoff, and after every (re)connect it runs
// LISTEN first and then a resync: one ChangeKeys, and a ChangeJTIRevoked for
// each jti revoked since the connection was lost (less resyncSkew), because
// NOTIFY does not queue for a listener that is away. KEYS_RELOAD_INTERVAL
// and the denylist cache TTL remain the correctness backstop.
func (s *Store) SubscribeChanges(ctx context.Context) <-chan keys.Change {
	ch := s.changes.Subscribe(ctx)
	s.feedOnce.Do(func() {
		feedCtx, cancel := context.WithCancel(context.Background())
		s.stopFeed = cancel
		go func() {
			defer close(s.feedDone)
			s.runFeed(feedCtx)
		}()
	})
	select {
	case <-s.feedUp:
	case <-ctx.Done():
	}
	return ch
}

func (s *Store) runFeed(ctx context.Context) {
	since := clock.Now()
	up := s.feedUp
	defer func() {
		if up != nil {
			close(up)
		}
	}()

	retry := feedRetryMin
	for {
		connected := false
		err := s.listenOnce(ctx, since, func() {
			connected = true
			if up != nil {
				close(up)
				up = nil
			}
		})
		if ctx.Err() != nil {
			return
		}
		if up != nil {
			close(up) // the first attempt failed: stop holding SubscribeChanges
			up = nil
		}
		if connected {
			since, retry = clock.Now(), feedRetryMin
		}
		s.logger.Warn("change feed connection lost; reconnecting (keys and the denylist still reload on their timers)",
			zap.Error(err), zap.Duration("retry_in", retry))
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
		retry = min(2*retry, feedRetryMax)
	}
}

// listenOnce connects, listens and resyncs, calls up, then relays
// notifications until the connection fails or ctx ends.
func (s *Store) listenOnce(ctx context.Context, since time.Time, up func()) error {
	src := s.listen
	src.logger = zap.NewNop() // New already warned about an allowed insecure sslmode
	cfg, err := src.connConfig()
	if err != nil {
		return err
	}
	if _, set := cfg.RuntimeParams["application_name"]; !set {
		cfg.RuntimeParams["application_name"] = feedApplicationName
	}
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return fmt.Errorf("postgres: connect change feed: %w", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()
	registerUTC(conn)

	if _, err := conn.Exec(ctx, `LISTEN `+changeChannel); err != nil {
		return fmt.Errorf("postgres: listen: %w", err)
	}
	up()
	if err := s.resync(ctx, conn, since.Add(-resyncSkew)); err != nil {
		return err
	}

	for {
		waitCtx, cancel := context.WithTimeout(ctx, feedPing)
		n, err := conn.WaitForNotification(waitCtx)
		cancel()
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, context.DeadlineExceeded):
			if err := conn.Ping(ctx); err != nil {
				return fmt.Errorf("postgres: ping change feed: %w", err)
			}
		case err != nil:
			return fmt.Errorf("postgres: wait for notification: %w", err)
		default:
			if c, ok := decodeChange(n.Payload); ok {
				s.changes.Publish(c)
			}
		}
	}
}

// resync reports what a listener that was away may have missed.
func (s *Store) resync(ctx context.Context, conn *pgx.Conn, since time.Time) error {
	rows, err := conn.Query(ctx, `SELECT jti FROM jti_denylist WHERE revoked_at >= $1`, since)
	if err != nil {
		return fmt.Errorf("postgres: resync change feed: %w", err)
	}
	jtis, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("postgres: resync change feed: %w", err)
	}
	s.changes.Publish(keys.Change{Kind: keys.ChangeKeys})
	for _, jti := range jtis {
		s.changes.Publish(keys.Change{Kind: keys.ChangeJTIRevoked, JTI: jti})
	}
	return nil
}
