package sqlite

import (
	"context"
	"time"

	"github.com/onhotpath/tempogate/admin"
)

// adminKeyRegistry adapts *Store to admin.KeyRegistry. The interface uses
// short, domain-local method names (Save / ByID / List / MarkRevoked) so the
// consumer reads naturally; *Store uses prefixed names
// (SaveIntegrationKey, IntegrationKeyByID, ...) so multiple consumer
// interfaces can coexist on the same concrete type without identifier
// collisions. This shim performs the per-call translation.
//
// The pattern (short consumer name + prefixed Store method + thin shim in
// state/sqlite) is the project convention for any future consumer added
// after admin/. See state/doc.go for the rationale.
type adminKeyRegistry struct {
	s *Store
}

// NewAdminKeyRegistry is the admin.KeyRegistry sqlite.Fx binds over s.
func NewAdminKeyRegistry(s *Store) admin.KeyRegistry { return &adminKeyRegistry{s: s} }

func (a *adminKeyRegistry) Save(ctx context.Context, k admin.IntegrationKey) error {
	return a.s.SaveIntegrationKey(ctx, k)
}

func (a *adminKeyRegistry) ByID(ctx context.Context, id string) (admin.IntegrationKey, error) {
	return a.s.IntegrationKeyByID(ctx, id)
}

func (a *adminKeyRegistry) List(ctx context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	return a.s.ListIntegrationKeys(ctx, f)
}

func (a *adminKeyRegistry) MarkRevoked(ctx context.Context, id string, at time.Time) (string, error) {
	return a.s.MarkIntegrationKeyRevoked(ctx, id, at)
}

// adminSessionStore adapts *Store to admin.SessionStore over the same
// methods `tempogate sessions` calls, so both surfaces revoke identically.
type adminSessionStore struct {
	s *Store
}

// NewAdminSessionStore is the admin.SessionStore sqlite.Fx binds over s.
func NewAdminSessionStore(s *Store) admin.SessionStore { return &adminSessionStore{s: s} }

func (a *adminSessionStore) List(ctx context.Context, f admin.SessionFilter, now time.Time) ([]admin.Session, error) {
	rows, err := a.s.ListRefreshSessions(ctx, RefreshSessionFilter{Email: f.Email, Subject: f.Subject}, now)
	if err != nil {
		return nil, err
	}
	out := make([]admin.Session, 0, len(rows))
	for _, r := range rows {
		out = append(out, admin.Session(r))
	}
	return out, nil
}

func (a *adminSessionStore) RevokeFamily(ctx context.Context, familyID string, at time.Time) (int, error) {
	return a.s.RevokeRefreshFamily(ctx, familyID, at)
}

func (a *adminSessionStore) RevokeEmail(ctx context.Context, email string, at time.Time) (int, error) {
	return a.s.RevokeRefreshByEmail(ctx, email, at)
}

func (a *adminSessionStore) RevokeSubject(ctx context.Context, subject string, at time.Time) (int, error) {
	return a.s.RevokeRefreshBySubject(ctx, subject, at)
}
