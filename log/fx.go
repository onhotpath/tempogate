package log

import (
	"go.uber.org/dig"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
)

func Fx() fx.Option {
	return fx.Provide(New)
}

// Failure logs err at error level led by its root cause: a dig error's text
// is every constructor and parameter on the path to the one that failed,
// which buries the cause. At debug the whole chain follows as errorChain.
func Failure(z *zap.Logger, msg string, err error) {
	root := dig.RootCause(err)
	fields := []zap.Field{zap.Error(root)}
	if root != err && z.Core().Enabled(zap.DebugLevel) {
		fields = append(fields, zap.NamedError("errorChain", err))
	}
	z.Error(msg, fields...)
}

// FxLoggerOption configures FxLogger.
type FxLoggerOption func(*fxLogger)

// ErrorsReturned is for an fx app whose caller takes every error from
// app.Err, Start and Stop and logs it itself, so fx logging any of them would
// only repeat it.
func ErrorsReturned() FxLoggerOption {
	return func(l *fxLogger) { l.returned = true }
}

// FxLogger is fx's event logger. fx's own lifecycle events are noise outside
// development, so only failures are logged, and each failure once: a failed
// constructor surfaces as its own event, again as the invoke that needed it,
// and again as the start that failed, so all but the last go to debug.
func FxLogger(z *zap.Logger, opts ...FxLoggerOption) fxevent.Logger {
	debug := &fxevent.ZapLogger{Logger: z}
	debug.UseErrorLevel(zap.DebugLevel)
	l := &fxLogger{
		z:      z,
		events: &fxevent.ZapLogger{Logger: z.WithOptions(zap.IncreaseLevel(zap.WarnLevel))},
		debug:  debug,
	}
	for _, o := range opts {
		o(l)
	}
	return l
}

type fxLogger struct {
	z      *zap.Logger
	events *fxevent.ZapLogger
	debug  *fxevent.ZapLogger
	// returned is set by ErrorsReturned.
	returned bool
}

func (l *fxLogger) LogEvent(event fxevent.Event) {
	if !l.returned {
		switch e := event.(type) {
		case *fxevent.Started:
			if e.Err != nil {
				Failure(l.z, "start failed", e.Err)
				return
			}
		case *fxevent.Stopped:
			if e.Err != nil {
				l.events.LogEvent(e)
				return
			}
		}
	}
	if failed(event) {
		l.debug.LogEvent(event)
		return
	}
	l.events.LogEvent(event)
}

// failed reports whether event records an error. Every such error also
// reaches app.Err, Start or Stop, so it is logged there.
func failed(event fxevent.Event) bool {
	switch e := event.(type) {
	case *fxevent.Supplied:
		return e.Err != nil
	case *fxevent.Provided:
		return e.Err != nil
	case *fxevent.Replaced:
		return e.Err != nil
	case *fxevent.Decorated:
		return e.Err != nil
	case *fxevent.Run:
		return e.Err != nil
	case *fxevent.Invoked:
		return e.Err != nil
	case *fxevent.OnStartExecuted:
		return e.Err != nil
	case *fxevent.OnStopExecuted:
		return e.Err != nil
	case *fxevent.RollingBack:
		return true
	case *fxevent.RolledBack:
		return e.Err != nil
	case *fxevent.Started:
		return e.Err != nil
	case *fxevent.Stopped:
		return e.Err != nil
	}
	return false
}
