// Package instrument is what both state backends record about their
// operations, declared once so state/sqlite and state/postgres expose the
// same series.
package instrument

import (
	"context"

	"github.com/onhotpath/tempogate/observe"
)

// Ops counts store operations that failed with a database error, under a
// fixed op name (e.g. "consume_refresh"). Not-found results are protocol
// outcomes, not errors, and are never counted. The zero value records
// nothing.
type Ops struct {
	errors observe.Counter[opLabels]
}

// New declares the instruments on m. A nil m records nothing.
func New(m observe.Meter) (*Ops, error) {
	errs, err := observe.NewCounter[opLabels](m, "tempogate.db_errors",
		observe.WithDescription("State store operations that failed, by operation. Not-found results are not errors."))
	if err != nil {
		return nil, err
	}
	return &Ops{errors: errs}, nil
}

// Fail counts op as failed and returns err unchanged, so call sites keep
// their own error context.
func (o *Ops) Fail(ctx context.Context, op string, err error) error {
	o.errors.Inc(ctx, opLabels{op: op})
	return err
}

type opLabels struct{ op string }

func (l opLabels) Attrs() []observe.Attr {
	return []observe.Attr{observe.String("op", l.op)}
}
