package oidc_test

import (
	"context"
	"strings"
	"sync"

	"github.com/onhotpath/tempogate/perms"
)

// stubResolver is a PermissionResolver for tests: everyone gets grant except
// the emails listed in deny (case-insensitive), and err, when set, fails
// every call. It records the emails it was asked about.
type stubResolver struct {
	grant *perms.Grant
	err   error

	mu    sync.Mutex
	deny  map[string]bool
	asked []string
}

func (r *stubResolver) Resolve(_ context.Context, email string) (*perms.Grant, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, email)
	if r.err != nil {
		return nil, r.err
	}
	if r.deny[strings.ToLower(email)] {
		return perms.New(), nil
	}
	return r.grant, nil
}

// denyEmail makes later calls for email resolve to nothing.
func (r *stubResolver) denyEmail(email string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.deny == nil {
		r.deny = map[string]bool{}
	}
	r.deny[strings.ToLower(email)] = true
}

func (r *stubResolver) calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asked...)
}

// newStubResolver grants the claim entries to everyone.
func newStubResolver(claim ...string) *stubResolver {
	g, err := perms.ParseClaim(claim)
	if err != nil {
		panic(err)
	}
	return &stubResolver{grant: g}
}

// permitAll is the resolver the tests that are not about authorization use:
// every admitted person is cluster admin, as before rules existed.
var permitAll = newStubResolver("temporal-system:admin")
