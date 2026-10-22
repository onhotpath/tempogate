package api_test

import (
	"context"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/onhotpath/tempogate/api"
)

type probeFunc func(context.Context) error

func (f probeFunc) Probe(ctx context.Context) error { return f(ctx) }

func TestReadyz_503WhenStoreProbeFails(t *testing.T) {
	t.Parallel()
	var healthy atomic.Bool
	healthy.Store(true)
	r := api.NewReadiness(api.WithStoreProbe(probeFunc(func(context.Context) error {
		if healthy.Load() {
			return nil
		}
		return errors.New("sqlite: unable to open database file: /var/lib/tempogate/state.db")
	})))
	r.Mark()
	srv, cleanup := newTestServer(t, r)
	defer cleanup()

	code, _ := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusOK, code)

	healthy.Store(false)
	code, body := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code, "an unusable state store must take the pod out of rotation")
	assert.NotContains(t, string(body), "/var/lib/tempogate", "probe errors must not leak on the public listener")

	// Liveness never consults the store: restarting the process cannot fix
	// a missing volume, so a DB outage must not trigger a restart loop.
	code, _ = get(t, srv.URL+"/healthz")
	assert.Equal(t, http.StatusOK, code)

	healthy.Store(true)
	code, _ = get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusOK, code, "readiness recovers with the store")
}

// The probe gets a deadline well inside the kubelet's default 1s probe
// timeout, so a wedged store answers 503 instead of hanging the probe.
func TestReadyz_StoreProbeIsBounded(t *testing.T) {
	t.Parallel()
	r := api.NewReadiness(api.WithStoreProbe(probeFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})))
	r.Mark()
	srv, cleanup := newTestServer(t, r)
	defer cleanup()

	start := time.Now()
	code, _ := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.Less(t, time.Since(start), time.Second)
}

func TestReadyz_StoreNotProbedBeforeListening(t *testing.T) {
	t.Parallel()
	var probed atomic.Bool
	r := api.NewReadiness(api.WithStoreProbe(probeFunc(func(context.Context) error {
		probed.Store(true)
		return nil
	})))
	srv, cleanup := newTestServer(t, r)
	defer cleanup()

	code, _ := get(t, srv.URL+"/readyz")
	assert.Equal(t, http.StatusServiceUnavailable, code)
	assert.False(t, probed.Load())
}
