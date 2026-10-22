package postgres

import (
	"context"
	"time"

	"github.com/onhotpath/tempogate/admin"
)

// adminKeyRegistry adapts *Store to admin.KeyRegistry: the consumer's short
// names over the store's prefixed ones, as in state/sqlite/admin_adapter.go.
type adminKeyRegistry struct {
	s *Store
}

// NewAdminKeyRegistry is the admin.KeyRegistry postgres.Fx binds over s.
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

// adminSessionStore adapts *Store to admin.SessionStore, which the admin
// API and the `tempogate sessions` CLI both use.
type adminSessionStore struct {
	s *Store
}

// NewAdminSessionStore is the admin.SessionStore postgres.Fx binds over s.
func NewAdminSessionStore(s *Store) admin.SessionStore { return &adminSessionStore{s: s} }

func (a *adminSessionStore) List(ctx context.Context, f admin.SessionFilter, now time.Time) ([]admin.Session, error) {
	return a.s.ListRefreshSessions(ctx, f, now)
}

func (a *adminSessionStore) RevokeFamily(ctx context.Context, familyID string, at time.Time) (int, error) {
	return a.s.RevokeRefreshFamily(ctx, familyID, at)
}

func (a *adminSessionStore) RevokeEmail(ctx context.Context, email string, at time.Time) (int, error) {
	return a.s.RevokeRefreshByEmail(ctx, email, at)
}

func (a *adminSessionStore) RevokeSubject(ctx context.Context, connectorID, subject string, at time.Time) (int, error) {
	return a.s.RevokeRefreshBySubject(ctx, connectorID, subject, at)
}
