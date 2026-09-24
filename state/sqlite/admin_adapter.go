package sqlite

import (
	"context"

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

func newAdminKeyRegistry(s *Store) admin.KeyRegistry { return &adminKeyRegistry{s: s} }

func (a *adminKeyRegistry) Save(ctx context.Context, k admin.IntegrationKey) error {
	return a.s.SaveIntegrationKey(ctx, k)
}

func (a *adminKeyRegistry) ByID(ctx context.Context, id string) (admin.IntegrationKey, error) {
	return a.s.IntegrationKeyByID(ctx, id)
}

func (a *adminKeyRegistry) List(ctx context.Context, f admin.ListFilter) ([]admin.IntegrationKey, error) {
	return a.s.ListIntegrationKeys(ctx, f)
}

func (a *adminKeyRegistry) MarkRevoked(ctx context.Context, id string) (string, error) {
	return a.s.MarkIntegrationKeyRevoked(ctx, id)
}
