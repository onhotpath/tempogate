package api

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// defaultStoreProbeTimeout keeps a wedged store from outliving the kubelet's
// default 1s probe timeout: /readyz answers 503 instead of timing out.
const defaultStoreProbeTimeout = 500 * time.Millisecond

var (
	errNotListening     = errors.New("http listener not bound yet")
	errStoreUnavailable = errors.New("state store unavailable")
)

// StoreProbe reports whether the state store can serve requests right now.
// Every state backend's *Store satisfies it structurally (bound via fx.As
// in its Fx).
type StoreProbe interface {
	Probe(ctx context.Context) error
}

// Readiness backs /readyz: ready once the serve command has bound the public
// listener (Mark) and, on every call, only while the state store answers.
// Liveness (/healthz) deliberately ignores the store: a restart cannot bring
// back a missing volume, it would only turn an outage into a crash loop.
type Readiness struct {
	ready        atomic.Bool
	store        StoreProbe
	probeTimeout time.Duration
	logger       *zap.Logger
}

type ReadinessOption func(*Readiness)

// WithStoreProbe makes readiness depend on the state store. Nil keeps
// readiness listener-only.
func WithStoreProbe(p StoreProbe) ReadinessOption {
	return func(r *Readiness) { r.store = p }
}

// WithReadinessLogger logs why the store probe failed. The /readyz response
// itself stays generic: it is served on the public listener.
func WithReadinessLogger(l *zap.Logger) ReadinessOption {
	return func(r *Readiness) {
		if l != nil {
			r.logger = l
		}
	}
}

func NewReadiness(opts ...ReadinessOption) *Readiness {
	r := &Readiness{probeTimeout: defaultStoreProbeTimeout, logger: zap.NewNop()}
	for _, o := range opts {
		o(r)
	}
	return r
}

func (r *Readiness) Mark()         { r.ready.Store(true) }
func (r *Readiness) IsReady() bool { return r.ready.Load() }

// Check returns nil when the server should receive traffic.
func (r *Readiness) Check(ctx context.Context) error {
	if !r.IsReady() {
		return errNotListening
	}
	if r.store == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, r.probeTimeout)
	defer cancel()
	if err := r.store.Probe(ctx); err != nil {
		r.logger.Warn("readiness: state store probe failed", zap.Error(err))
		return errStoreUnavailable
	}
	return nil
}
