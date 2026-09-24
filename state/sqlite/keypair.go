package sqlite

import (
	"context"
	"errors"
	"fmt"

	sqlite3 "modernc.org/sqlite"
	sqlite3lib "modernc.org/sqlite/lib"

	"github.com/onhotpath/tempogate/keys"
)

// ErrDuplicateKid is returned by SaveKeypair when a keypair with the given
// kid already exists. Callers (e.g. `tempogate keys generate` without
// `--force`) must distinguish this from generic store errors.
var ErrDuplicateKid = errors.New("sqlite: keypair with this kid already exists")

func (s *Store) SaveKeypair(ctx context.Context, kp keys.Keypair) error {
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
		return fmt.Errorf("sqlite: save keypair: %w", err)
	}
	return nil
}

func (s *Store) LoadKeypairs(ctx context.Context) ([]keys.Keypair, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT kid, alg, private_pem, public_pem, created_at
		 FROM keypairs
		 ORDER BY created_at ASC, kid ASC`,
	)
	if err != nil {
		return nil, fmt.Errorf("sqlite: load keypairs: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var out []keys.Keypair
	for rows.Next() {
		var kp keys.Keypair
		if err := rows.Scan(&kp.Kid, &kp.Alg, &kp.PrivatePEM, &kp.PublicPEM, &kp.CreatedAt); err != nil {
			return nil, fmt.Errorf("sqlite: scan keypair: %w", err)
		}
		out = append(out, kp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sqlite: rows: %w", err)
	}
	return out, nil
}
