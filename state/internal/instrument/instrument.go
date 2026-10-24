// Package instrument is what both state backends record about their
// operations, declared once so state/sqlite and state/postgres expose the
// same series and spans.
package instrument

import (
	"context"

	"github.com/onhotpath/tempogate/observe"
)

// errorTypeDB is a failed operation's error.type.
const errorTypeDB = "db_error"

// Ops records store operations under a fixed op name (e.g.
// "consume_refresh"): a span for each one made inside a traced request, and
// a count of those that failed with a database error. Not-found results are
// protocol outcomes, not errors. The zero value records nothing.
type Ops struct {
	errors observe.Counter[opLabels]
	tracer observe.Tracer
}

// New declares the instruments on m and traces through t. Either may be nil.
func New(m observe.Meter, t observe.Tracer) (*Ops, error) {
	errs, err := observe.NewCounter[opLabels](m, "tempogate.db_errors",
		observe.WithDescription("State store operations that failed, by operation. Not-found results are not errors."))
	if err != nil {
		return nil, err
	}
	return &Ops{errors: errs, tracer: t}, nil
}

// Start begins one operation, which then runs under the returned context.
// Every method that touches the database runs as one:
//
//	ctx, op := s.ops.Start(ctx, "save_refresh")
//	defer op.End()
func (o *Ops) Start(ctx context.Context, name string) (context.Context, *Op) {
	var span observe.Span = observe.NopSpan{}
	if o.tracer != nil {
		ctx, span = o.tracer.Start(ctx, "store "+name,
			observe.WithAttributes(observe.String("tempogate.store.op", name)))
	}
	return ctx, &Op{ctx: ctx, ops: o, name: name, span: span}
}

// Op is one operation in progress.
type Op struct {
	ctx  context.Context
	ops  *Ops
	name string
	span observe.Span
	err  error
}

// Fail marks the operation failed with err and returns err unchanged, so
// call sites keep their own error context.
func (op *Op) Fail(err error) error {
	op.err = err
	return err
}

// End records the outcome. Call it exactly once.
func (op *Op) End() {
	if op.err != nil {
		op.ops.errors.Inc(op.ctx, opLabels{op: op.name})
		op.span.Fail(errorTypeDB, op.err)
	}
	op.span.End()
}

type opLabels struct{ op string }

func (l opLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("op", l.op)}
}
