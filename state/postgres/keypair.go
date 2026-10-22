package postgres

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/onhotpath/tempogate/keys"
)

// ErrDuplicateKid is returned by SaveKeypair when a keypair with the given
// kid already exists. Callers (e.g. `tempogate keys generate` without
// `--force`) must distinguish this from generic store errors.
var ErrDuplicateKid = errors.New("postgres: keypair with this kid already exists")

// keyBootstrapLockID is the pg_advisory_xact_lock key LockKeyBootstrap
// holds, distinct from migrationLockID.
const keyBootstrapLockID int64 = 0x7467626f6f747374 // "tgbootst"

func (s *Store) SaveKeypair(ctx context.Context, kp keys.Keypair) error {
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO keypairs (kid, alg, private_pem, public_pem, created_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			kp.Kid, kp.Alg, kp.PrivatePEM, kp.PublicPEM, kp.CreatedAt,
		); err != nil {
			return err
		}
		return notify(ctx, tx, keys.Change{Kind: keys.ChangeKeys})
	})
	if isUniqueViolation(err) {
		return fmt.Errorf("%w: %s", ErrDuplicateKid, kp.Kid)
	}
	if err != nil {
		return s.fail("save_keypair", fmt.Errorf("postgres: save keypair: %w", err))
	}
	return nil
}

func (s *Store) LoadKeypairs(ctx context.Context) ([]keys.Keypair, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+keypairColumns+`
		 FROM keypairs
		 ORDER BY created_at ASC, kid ASC`,
	)
	if err != nil {
		return nil, s.fail("load_keypairs", fmt.Errorf("postgres: load keypairs: %w", err))
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (keys.Keypair, error) { return scanKeypair(r) })
	if err != nil {
		return nil, s.fail("load_keypairs", fmt.Errorf("postgres: load keypairs: %w", err))
	}
	return out, nil
}

// UpdateKeypairPrivatePEM rewrites one keypair's private half in place, for
// `tempogate keys encrypt`.
func (s *Store) UpdateKeypairPrivatePEM(ctx context.Context, kid string, privatePEM []byte) error {
	errNoKid := fmt.Errorf("postgres: update keypair: no keypair with kid %s", kid)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE keypairs SET private_pem = $1 WHERE kid = $2`, privatePEM, kid)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNoKid
		}
		return notify(ctx, tx, keys.Change{Kind: keys.ChangeKeys})
	})
	if errors.Is(err, errNoKid) {
		return err
	}
	if err != nil {
		return s.fail("update_keypair_private_pem", fmt.Errorf("postgres: update keypair: %w", err))
	}
	return nil
}

// RetireKeypair stamps retired_at on kid. It first locks every active
// keypair row (in kid order, so concurrent retirements cannot deadlock), so
// two replicas retiring the last two active keys at once serialise: the
// second sees one active key left, its own, and is refused. An unknown kid
// wraps keys.ErrKeypairNotFound; an already retired one is returned
// unchanged, so the original grace window holds.
func (s *Store) RetireKeypair(ctx context.Context, kid string, at time.Time) (keys.Keypair, error) {
	var (
		kp      keys.Keypair
		changed bool
	)
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT kid FROM keypairs WHERE retired_at IS NULL ORDER BY kid FOR UPDATE`)
		if err != nil {
			return err
		}
		active, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		if len(active) > 1 && slices.Contains(active, kid) {
			if _, err := tx.Exec(ctx, `UPDATE keypairs SET retired_at = $1 WHERE kid = $2`, at, kid); err != nil {
				return err
			}
			changed = true
			if err := notify(ctx, tx, keys.Change{Kind: keys.ChangeKeys}); err != nil {
				return err
			}
		}
		kp, err = scanKeypair(tx.QueryRow(ctx, `SELECT `+keypairColumns+` FROM keypairs WHERE kid = $1`, kid))
		return err
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return keys.Keypair{}, fmt.Errorf("%w: %s", keys.ErrKeypairNotFound, kid)
	case err != nil:
		return keys.Keypair{}, s.fail("retire_keypair", fmt.Errorf("postgres: retire keypair: %w", err))
	case !changed && !kp.Retired():
		return keys.Keypair{}, fmt.Errorf("%w (kid=%s)", keys.ErrLastActiveKeypair, kid)
	}
	return kp, nil
}

// LockKeyBootstrap satisfies keys.BootstrapLocker: fn runs while this
// process holds keyBootstrapLockID, so replicas starting together on an
// empty database generate one signing key between them, not one each. The
// lock is a transaction-level advisory lock on one pooled connection; fn
// reads and writes through the others, which is why the pool needs at least
// two connections.
func (s *Store) LockKeyBootstrap(ctx context.Context, fn func(context.Context) error) error {
	var fnErr error
	err := s.inTx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, keyBootstrapLockID); err != nil {
			return err
		}
		fnErr = fn(ctx)
		return nil
	})
	if err != nil {
		return s.fail("lock_key_bootstrap", fmt.Errorf("postgres: lock key bootstrap: %w", err))
	}
	return fnErr
}

const keypairColumns = `kid, alg, private_pem, public_pem, created_at, retired_at`

func scanKeypair(r pgx.Row) (keys.Keypair, error) {
	var kp keys.Keypair
	if err := r.Scan(&kp.Kid, &kp.Alg, &kp.PrivatePEM, &kp.PublicPEM, &kp.CreatedAt, &kp.RetiredAt); err != nil {
		return keys.Keypair{}, err
	}
	return kp, nil
}
