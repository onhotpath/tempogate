package log

import (
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"go.uber.org/dig"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
)

func Fx() fx.Option {
	return fx.Provide(New)
}

// Failure logs err at error level as its summary (see summarize): a dig
// error's text is every constructor and parameter on the path to the one that
// failed, with file paths, which buries the cause. At debug the whole chain
// follows as errorChain.
func Failure(z *zap.Logger, msg string, err error) {
	s := summarize(err)
	fields := []zap.Field{zap.Error(s.err)}
	if s.in != "" {
		fields = append(fields, zap.String("in", s.in))
	}
	if s.dig && z.Core().Enabled(zap.DebugLevel) {
		fields = append(fields, zap.NamedError("errorChain", err))
	}
	z.Error(msg, fields...)
}

type summary struct {
	// err is the root cause, behind whatever err added above dig.
	err error
	// in is the path of types dig was building when it failed, or the
	// function it could not call.
	in string
	// dig is set when err held a dig error, so err is not the whole chain.
	dig bool
}

var digFunc = regexp.MustCompile(`function "(?:[^"]*/)?([^"/]*)"\.(\S+)`)

// summarize shortens a dig error to its root cause (dig.RootCause), keeps the
// text err adds above dig (as in fmt.Errorf("migrate: %w", err)), and names
// where dig failed: the types it was building, outermost first, or for a
// missing dependency of an invoked function, that function. Any other error
// is returned as it is. The walk is bounded, so a cyclic chain cannot hang it.
func summarize(err error) summary {
	d := findDig(err)
	if d == nil {
		return summary{err: err}
	}
	var path []string
	fn := ""
	var e error = d
	for range maxErrorNodes {
		own, causes := unwrap(e)
		switch {
		case strings.HasPrefix(own, "failed to build "):
			path = append(path, strings.TrimPrefix(own, "failed to build "))
		case strings.HasPrefix(own, "could not build value group "):
			path = append(path, strings.TrimPrefix(own, "could not build value group "))
		case strings.HasPrefix(own, "missing dependencies for function "):
			if m := digFunc.FindStringSubmatch(own); m != nil {
				fn = m[1] + "." + m[2]
			}
		}
		if len(causes) != 1 {
			break
		}
		e = causes[0]
		if _, ok := e.(dig.Error); !ok {
			break
		}
	}
	s := summary{err: e, in: strings.Join(path, " > "), dig: true}
	if s.in == "" {
		s.in = fn
	}
	if top, inner := errorText(err), errorText(d); top != inner && strings.HasSuffix(top, inner) {
		s.err = fmt.Errorf("%s%w", strings.TrimSuffix(top, inner), e)
	}
	return s
}

// findDig returns the outermost dig.Error in err's tree, visiting at most
// maxErrorNodes errors.
func findDig(err error) dig.Error {
	queue := []error{err}
	for i := 0; i < len(queue) && i < maxErrorNodes; i++ {
		if d, ok := queue[i].(dig.Error); ok {
			return d
		}
		_, causes := unwrap(queue[i])
		queue = append(queue, causes...)
	}
	return nil
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

var errorType = reflect.TypeFor[error]()

// failed reports whether event records an error, in any field of type error
// (Err on most events, StartErr on RollingBack), so an event type added to fx
// later is covered too. Every such error also reaches app.Err, Start or Stop,
// so it is logged there.
func failed(event fxevent.Event) bool {
	v := reflect.Indirect(reflect.ValueOf(event))
	if v.Kind() != reflect.Struct {
		return false
	}
	for i := range v.NumField() {
		if f := v.Field(i); f.Type() == errorType && !f.IsNil() {
			return true
		}
	}
	return false
}

// BootLogger is the root graph's fx event logger. When the constructor given
// to fx.WithLogger fails, fx falls back to its own console logger, which
// prints every provide and the whole dig chain; FxLogger needs the zap logger,
// and so a valid LOG_LEVEL and LOG_FORMAT. BootLogger depends on nothing: it
// holds fx's events until Use hands it the zap logger, then passes them on to
// FxLogger. If the graph fails before that, it writes only the failure, as one
// line, to w.
type BootLogger struct {
	w    io.Writer
	name string

	mu   sync.Mutex
	next fxevent.Logger
	held []fxevent.Event
}

// NewBootLogger returns a BootLogger that prefixes its one line with name.
func NewBootLogger(w io.Writer, name string) *BootLogger {
	return &BootLogger{w: w, name: name}
}

// Use passes the held events, and every later one, to FxLogger(z).
func (b *BootLogger) Use(z *zap.Logger) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.next = FxLogger(z)
	for _, e := range b.held {
		b.next.LogEvent(e)
	}
	b.held = nil
}

func (b *BootLogger) LogEvent(event fxevent.Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.next != nil {
		b.next.LogEvent(event)
		return
	}
	if e, ok := event.(*fxevent.Started); ok && e.Err != nil {
		_, _ = fmt.Fprintf(b.w, "%s: %s\n", b.name, escapeControls(errorText(summarize(e.Err).err), false))
		return
	}
	b.held = append(b.held, event)
}
