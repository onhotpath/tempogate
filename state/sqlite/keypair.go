package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/onhotpath/tempogate/keys"
)

// ErrDuplicateKid is returned by SaveKeypair when a keypair with the given
// kid already exists. Callers (e.g. `tempogate keys generate` without
// `--force`) must distinguish this from generic store errors.
var ErrDuplicateKid = errors.New("sqlite: keypair with this kid already exists")

func (s *Store) SaveKeypair(ctx context.Context, kp keys.Keypair) error {
	ctx, op := s.ops.Start(ctx, "save_keypair")
	defer op.End()
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO keypairs (kid, alg, private_pem, public_pem, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		kp.Kid, kp.Alg, kp.PrivatePEM, kp.PublicPEM, kp.CreatedAt,
	)
	if err != nil {
		var sqliteErr *sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code() == sqlite3lib.SQLITE_CONSTRAINT_PRIMARYKEY {
			return fmt.Errorf("%w: %s", ErrDuplicateKid, kp.Kid)
		}
		return op.Fail(fmt.Errorf("sqlite: save keypair: %w", err))
	}
	s.changes.Publish(keys.Change{Kind: keys.ChangeKeys})
	return nil
}

func (s *Store) LoadKeypairs(ctx context.Context) ([]keys.Keypair, error) {
	ctx, op := s.ops.Start(ctx, "load_keypairs")
	defer op.End()
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+keypairColumns+`
		 FROM keypairs
		 ORDER BY created_at ASC, kid ASC`,
	)
	if err != nil {
		return nil, op.Fail(fmt.Errorf("sqlite: load keypairs: %w", err))
	}
	defer func() { _ = rows.Close() }()

	var out []keys.Keypair
	for rows.Next() {
		kp, err := scanKeypair(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, kp)
	}
	if err := rows.Err(); err != nil {
		return nil, op.Fail(fmt.Errorf("sqlite: rows: %w", err))
	}
	return out, nil
}

// UpdateKeypairPrivatePEM rewrites one keypair's private half in place, for
// `tempogate keys encrypt`.
func (s *Store) UpdateKeypairPrivatePEM(ctx context.Context, kid string, privatePEM []byte) error {
	ctx, op := s.ops.Start(ctx, "update_keypair_private_pem")
	defer op.End()
	res, err := s.db.ExecContext(ctx, `UPDATE keypairs SET private_pem = ? WHERE kid = ?`, privatePEM, kid)
	if err != nil {
		return op.Fail(fmt.Errorf("sqlite: update keypair: %w", err))
	}
	n, err := res.RowsAffected()
	if err != nil {
		return op.Fail(fmt.Errorf("sqlite: update keypair: %w", err))
	}
	if n == 0 {
		return fmt.Errorf("sqlite: update keypair: no keypair with kid %s", kid)
	}
	s.changes.Publish(keys.Change{Kind: keys.ChangeKeys})
	return nil
}

// RetireKeypair stamps retired_at on kid. The guard against retiring the last
// active keypair lives in the UPDATE itself, so two processes retiring the
// last two active keys at once cannot leave the signer with none. When no
// row changes, a follow-up read says why: unknown kid, already retired
// (returned unchanged so the original grace window holds), or last active.
func (s *Store) RetireKeypair(ctx context.Context, kid string, at time.Time) (keys.Keypair, error) {
	ctx, op := s.ops.Start(ctx, "retire_keypair")
	defer op.End()
	res, err := s.db.ExecContext(ctx,
		`UPDATE keypairs SET retired_at = ?
		 WHERE kid = ? AND retired_at IS NULL
		   AND EXISTS (SELECT 1 FROM keypairs WHERE kid <> ? AND retired_at IS NULL)`,
		at, kid, kid,
	)
	if err != nil {
		return keys.Keypair{}, op.Fail(fmt.Errorf("sqlite: retire keypair: %w", err))
	}
	changed, err := res.RowsAffected()
	if err != nil {
		return keys.Keypair{}, op.Fail(fmt.Errorf("sqlite: retire keypair: %w", err))
	}
	if changed > 0 {
		s.changes.Publish(keys.Change{Kind: keys.ChangeKeys})
	}

	kp, err := scanKeypair(s.db.QueryRowContext(ctx,
		`SELECT `+keypairColumns+` FROM keypairs WHERE kid = ?`, kid))
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return keys.Keypair{}, fmt.Errorf("%w: %s", keys.ErrKeypairNotFound, kid)
	case err != nil:
		return keys.Keypair{}, err
	case changed == 0 && !kp.Retired():
		return keys.Keypair{}, fmt.Errorf("%w (kid=%s)", keys.ErrLastActiveKeypair, kid)
	}
	return kp, nil
}

const keypairColumns = `kid, alg, private_pem, public_pem, created_at, retired_at`

// rowScanner is the Scan half shared by *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanKeypair(r rowScanner) (keys.Keypair, error) {
	var (
		kp      keys.Keypair
		retired sql.NullTime
	)
	if err := r.Scan(&kp.Kid, &kp.Alg, &kp.PrivatePEM, &kp.PublicPEM, &kp.CreatedAt, &retired); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return keys.Keypair{}, err
		}
		return keys.Keypair{}, fmt.Errorf("sqlite: scan keypair: %w", err)
	}
	if retired.Valid {
		t := retired.Time
		kp.RetiredAt = &t
	}
	return kp, nil
}
