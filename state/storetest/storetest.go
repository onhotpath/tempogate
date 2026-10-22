// Package storetest is the conformance suite for state backends. It turns
// the contracts in package state (state/doc.go) into tests that reach a
// backend only through the consumer-side interfaces, so the same suite runs
// unchanged against every backend: SQLite from this package's own tests, and
// each further backend from its own package's tests.
//
// A backend passes when Run and CheckNoSQLClock both pass against it.
package storetest

import (
	"sync"
	"testing"
	"time"

	"github.com/onhotpath/tempogate/admin"
	"github.com/onhotpath/tempogate/api"
	"github.com/onhotpath/tempogate/keys"
	"github.com/onhotpath/tempogate/oidc"
)

// Store is every consumer interface the state store backs through fx.As
// (see state/doc.go), plus keys.PrivateKeyRewriter for `keys encrypt`.
type Store interface {
	keys.KeyStore
	keys.PrivateKeyRewriter
	keys.DenylistChecker
	oidc.AuthRequestStore
	oidc.CallbackStore
	oidc.TokenStore
	oidc.DeviceCodeStore
	oidc.BrowserSessionStore
	api.StoreProbe
}

// Backend is one fresh, migrated, empty store under test, with the admin
// adapters the backend binds over it.
type Backend struct {
	Store       Store
	KeyRegistry admin.KeyRegistry
	Sessions    admin.SessionStore

	// Changes is the backend's change feed, or nil when it has none; the
	// change-notification cases are then skipped.
	Changes keys.ChangeFeed
}

// NewBackend returns an empty backend for one test case, registering its
// teardown with t.Cleanup.
type NewBackend func(t *testing.T) Backend

type testCase struct {
	name string
	run  func(t *testing.T, b Backend)
}

// Run runs every conformance case as a subtest, each on its own backend.
func Run(t *testing.T, newBackend NewBackend) {
	t.Helper()
	groups := [][]testCase{
		timeCases(),
		keyCases(),
		authFlowCases(),
		refreshCases(),
		sessionCases(),
		deviceCodeCases(),
		integrationKeyCases(),
		changeCases(),
	}
	for _, g := range groups {
		for _, c := range g {
			t.Run(c.name, func(t *testing.T) { c.run(t, newBackend(t)) })
		}
	}
}

// t0 is the instant the suite builds every row around. It is far from the
// wall clock and carries microseconds, so a backend that stamps its own clock
// or keeps less than microsecond precision cannot pass by accident.
var t0 = time.Date(2001, 2, 3, 4, 5, 6, 123456000, time.UTC)

// racers is how many goroutines a concurrency case releases at once.
const racers = 32

// race calls fn from racers goroutines released together and returns each
// call's error, indexed by i.
func race(fn func(i int) error) []error {
	errs := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs[i] = fn(i)
		}()
	}
	close(start)
	wg.Wait()
	return errs
}

// winners counts the nil errors in errs.
func winners(errs []error) int {
	n := 0
	for _, err := range errs {
		if err == nil {
			n++
		}
	}
	return n
}
