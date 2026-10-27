package log

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 1, 2, 15, 4, 5, 6e6, time.UTC) }

func (fixedClock) NewTicker(d time.Duration) *time.Ticker { return time.NewTicker(d) }

func prettyLogger(color bool) (*zap.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	core := newCore(FormatPretty, color, zapcore.AddSync(&buf), zapcore.DebugLevel)
	return zap.New(core, zap.WithClock(fixedClock{})), &buf
}

// verboseError is what dig's errors look like to zap: a fmt.Formatter whose
// %+v differs from its message.
type verboseError struct{ cause error }

func (e verboseError) Error() string { return "could not build: " + e.cause.Error() }
func (e verboseError) Unwrap() error { return e.cause }
func (e verboseError) Format(s fmt.State, _ rune) {
	if s.Flag('+') {
		_, _ = io.WriteString(s, "could not build\n\t/src/graph.go:66:\n"+e.cause.Error())
		return
	}
	_, _ = io.WriteString(s, e.Error())
}

type panicError struct{}

func (*panicError) Error() string { panic("boom") }

type valuePanicError struct{}

func (valuePanicError) Error() string { panic("boom") }

// nilPointerError is the usual typed nil: a value-receiver Error on a nil
// pointer.
type nilPointerError struct{ msg string }

func (e nilPointerError) Error() string { return e.msg }

// loopError's Unwrap returns next, or itself when next is nil.
type loopError struct {
	msg  string
	next error
}

func (e *loopError) Error() string { return e.msg }
func (e *loopError) Unwrap() error {
	if e.next == nil {
		return e
	}
	return e.next
}

// joinLoop is a join whose Unwrap reaches back to itself; its Error does not
// follow the loop, as errors.Join's would.
type joinLoop struct{ errs []error }

func (e *joinLoop) Error() string   { return "a\nb" }
func (e *joinLoop) Unwrap() []error { return e.errs }

// sliceError has a slice as its dynamic type, so == on it panics; its Unwrap
// returns itself, which only the visit budget can stop.
type sliceError []string

func (e sliceError) Error() string { return strings.Join(e, ",") }
func (e sliceError) Unwrap() error { return e }

// multiError has go.uber.org/multierr's shape.
type multiError []error

func (m multiError) Error() string   { return errors.Join(m...).Error() }
func (m multiError) Errors() []error { return m }

func TestPretty_ErrorChain(t *testing.T) {
	z, buf := prettyLogger(false)
	err := fmt.Errorf("sqlite: create state directory: %w",
		&fs.PathError{Op: "mkdir", Path: "/var/lib/tempogate", Err: syscall.EACCES})

	z.Error("command failed", zap.Error(err), zap.String("dir", "/var/lib"), zap.Int("n", 2))

	assert.Equal(t, "15:04:05.006 ERROR command failed dir=/var/lib n=2\n"+
		"  error: sqlite: create state directory\n"+
		"    ↳ mkdir /var/lib/tempogate\n"+
		"      ↳ permission denied\n", buf.String())
}

func TestPretty_JoinedErrorsAreSiblings(t *testing.T) {
	for name, err := range map[string]error{
		"errors.Join": errors.Join(errors.New("a"), fmt.Errorf("b: %w", errors.New("c"))),
		"multierr":    multiError{errors.New("a"), fmt.Errorf("b: %w", errors.New("c"))},
	} {
		t.Run(name, func(t *testing.T) {
			z, buf := prettyLogger(false)
			z.Warn("stop", zap.Error(err))
			assert.Equal(t, "15:04:05.006 WARN stop\n"+
				"  error:\n"+
				"    ↳ a\n"+
				"    ↳ b\n"+
				"      ↳ c\n", buf.String())
		})
	}
}

func TestPretty_WrapperNestsUnderItsContext(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Error(fmt.Errorf("serve: %w", errors.Join(errors.New("a"), errors.New("b")))))
	assert.Equal(t, "15:04:05.006 ERROR stop\n"+
		"  error: serve\n"+
		"    ↳ a\n"+
		"    ↳ b\n", buf.String())
}

// A sentinel followed by its detail reads as one sentence; splitting it would
// put the detail above the sentinel.
func TestPretty_SentinelWithDetailStaysWhole(t *testing.T) {
	z, buf := prettyLogger(false)
	sentinel := errors.New("oidc: client not registered")
	z.Error("stop", zap.Error(fmt.Errorf("%w: %s", sentinel, "tempogate-cli")))
	assert.Equal(t, "15:04:05.006 ERROR stop\n"+
		"  error: oidc: client not registered: tempogate-cli\n", buf.String())
}

func TestPretty_FormatterErrorHasNoVerbose(t *testing.T) {
	err := verboseError{cause: errors.New("permission denied")}
	z, buf := prettyLogger(false)

	z.Error("direct", zap.Error(err))
	z.With(zap.Error(err)).Error("with")
	assert.Equal(t, "15:04:05.006 ERROR direct\n"+
		"  error: could not build\n"+
		"    ↳ permission denied\n"+
		"15:04:05.006 ERROR with\n"+
		"  error: could not build\n"+
		"    ↳ permission denied\n", buf.String())

	// slog stamps its own time, so only the rest of the line is fixed.
	buf.Reset()
	slog.New(zapslog.NewHandler(z.Core())).With("err", err).Error("slog")
	assert.Contains(t, buf.String(), " ERROR slog\n  err: could not build\n    ↳ permission denied\n")
	assert.NotContains(t, buf.String(), "errVerbose")
	assert.NotContains(t, buf.String(), "graph.go")
}

func TestPretty_MultiLineStringIsABlock(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Debug("invoke failed",
		zap.String("stack", "main.run\n\t/src/main.go:10\nmain.main\n\t/src/main.go:3\n"),
		zap.String("function", "main.run()"))

	out := buf.String()
	assert.NotContains(t, out, `\n`)
	assert.NotContains(t, out, `\t`)
	assert.Equal(t, "15:04:05.006 DEBUG invoke failed function=main.run()\n"+
		"  stack:\n"+
		"    main.run\n"+
		"    \t/src/main.go:10\n"+
		"    main.main\n"+
		"    \t/src/main.go:3\n", out)
}

func TestPretty_EntryStack(t *testing.T) {
	buf, err := newPrettyEncoder(false).EncodeEntry(zapcore.Entry{
		Level:   zapcore.ErrorLevel,
		Time:    fixedClock{}.Now(),
		Message: "oops",
		Stack:   "main.f\n\t/src/main.go:1",
	}, nil)
	require.NoError(t, err)
	assert.Equal(t, "15:04:05.006 ERROR oops\n  stacktrace:\n    main.f\n    \t/src/main.go:1\n", buf.String())
}

func TestPretty_InlineFields(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Named("http").With(zap.String("listener", "public")).Info("http request",
		zap.String("ua", "curl/8 (x)"),
		zap.String("empty", ""),
		zap.Duration("duration", 1500*time.Millisecond),
		zap.Bool("ok", true),
		zap.Strings("list", []string{"a", "b"}),
		zap.Namespace("ns"),
		zap.Int("inner", 1),
	)
	assert.Equal(t, `15:04:05.006 INFO [http] http request listener=public ua="curl/8 (x)" empty="" `+
		`duration=1.5s ok=true list=["a","b"] ns.inner=1`+"\n", buf.String())
}

func TestPretty_PanickingErrorIsRecovered(t *testing.T) {
	for name, err := range map[string]error{
		"pointer receiver": &panicError{},
		"value receiver":   valuePanicError{},
	} {
		t.Run(name, func(t *testing.T) {
			z, buf := prettyLogger(false)
			z.Error("stop", zap.Error(err))
			assert.Equal(t, "15:04:05.006 ERROR stop\n  error: PANIC=boom\n", buf.String())
		})
	}
}

// A typed nil reads as <nil>, as in zap's JSON.
func TestPretty_TypedNilError(t *testing.T) {
	for name, err := range map[string]error{
		"value receiver":   (*nilPointerError)(nil),
		"pointer receiver": (*panicError)(nil),
	} {
		t.Run(name, func(t *testing.T) {
			z, buf := prettyLogger(false)
			z.Error("stop", zap.Error(err))
			assert.Equal(t, "15:04:05.006 ERROR stop\n  error: <nil>\n", buf.String())
		})
	}
}

func TestPretty_CyclicErrors(t *testing.T) {
	self := &loopError{msg: "loop"}
	a := &loopError{msg: "a: b"}
	b := &loopError{msg: "b", next: a}
	a.next = b
	join := &joinLoop{}
	join.errs = []error{errors.New("a"), &loopError{msg: "b", next: join}}

	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"self":    {self, "  error: loop\n    ↳ … (cycle)\n"},
		"2-node":  {a, "  error: a\n    ↳ b\n      ↳ … (cycle)\n"},
		"join":    {join, "  error:\n    ↳ a\n    ↳ b\n      ↳ … (cycle)\n"},
		"slice":   {sliceError{"x"}, ""},
		"wrapped": {fmt.Errorf("ctx: %w", sliceError{"x"}), ""},
	} {
		t.Run(name, func(t *testing.T) {
			z, buf := prettyLogger(false)
			z.Error("stop", zap.Error(tc.err))
			if tc.want != "" {
				assert.Equal(t, "15:04:05.006 ERROR stop\n"+tc.want, buf.String())
			}
			assert.LessOrEqual(t, strings.Count(buf.String(), "\n"), maxErrorNodes+2)
		})
	}
}

// A chain deeper than the visit budget ends in a marker.
func TestPretty_DeepChainIsTruncated(t *testing.T) {
	err := errors.New("bottom")
	for i := range 10000 {
		err = fmt.Errorf("level %d: %w", i, err)
	}
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Error(err))

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	require.Len(t, lines, maxErrorNodes+2)
	assert.Equal(t, "  error: level 9999", lines[1])
	assert.Equal(t, strings.Repeat("  ", maxErrorNodes+1)+"↳ … (truncated)", lines[len(lines)-1])
	assert.NotContains(t, buf.String(), "bottom")
}

// Only the separator before a cause's text is trimmed; an error's own text is
// never otherwise changed.
func TestPretty_OwnTextIsKept(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Error(errors.New("--config is required:"))) //nolint:revive // the text under test
	z.Error("stop", zap.Error(fmt.Errorf("- ctx -; %w", errors.New("-cause-"))))
	assert.Equal(t, "15:04:05.006 ERROR stop\n  error: --config is required:\n"+
		"15:04:05.006 ERROR stop\n  error: - ctx -\n    ↳ -cause-\n", buf.String())
}

// Nothing a logged value carries reaches the terminal as a control
// character, and no newline outside a block starts a line of its own.
func TestPretty_EscapesControlCharacters(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Named("n\x1b[2J").Error("msg\x1b[2J\nfake 15:04:05.006 INFO line\r\x7f\u009b",
		zap.String("k\x1b\n", "v\x1b[2J\x9b"),
		zap.Strings("list", []string{"\x1b[2J\x7f\u009b"}),
		zap.Error(errors.New("bad\x1b[2J\nsecond\tline")),
		zap.String("block", "one\x1b[2J\ntwo\x07"),
	)
	out := buf.String()
	assert.Equal(t, `15:04:05.006 ERROR [n\x1b[2J] msg\x1b[2J\nfake 15:04:05.006 INFO line\r\x7f\x9b `+
		`k\x1b\n="v\x1b[2J\x9b" list=["\u001b[2J\u007f\u009b"]`+"\n"+
		"  error: bad\\x1b[2J\n    second\tline\n"+
		"  block:\n    one\\x1b[2J\n    two\\x07\n", out)
	for _, r := range out {
		assert.False(t, r != '\n' && r != '\t' && isControl(r, false), "control %U in %q", r, out)
	}
}

func TestPretty_ErrorsList(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Errors("errors", []error{
		verboseError{cause: errors.New("permission denied")},
		nil,
		errors.New("c"),
	}))
	assert.Equal(t, "15:04:05.006 ERROR stop\n"+
		"  errors:\n"+
		"    [0] could not build\n"+
		"      ↳ permission denied\n"+
		"    [2] c\n", buf.String())
}

type withError struct{ err error }

func (o withError) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	enc.AddString("op", "x")
	return enc.AddArray("errs", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		return arr.AppendObject(zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
			zap.Error(o.err).AddTo(enc)
			return nil
		}))
	}))
}

// An error nested in an object shows its plain text, with no errorVerbose.
func TestPretty_NestedErrorHasNoVerbose(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Object("obj", withError{verboseError{cause: errors.New("denied")}}))
	assert.Equal(t, `15:04:05.006 ERROR stop obj={"errs":[{"error":"could not build: denied"}],"op":"x"}`+"\n",
		buf.String())
}

func TestPretty_Color(t *testing.T) {
	z, buf := prettyLogger(true)
	z.Error("stop")
	assert.Contains(t, buf.String(), "\x1b[31mERROR\x1b[0m")

	z, buf = prettyLogger(false)
	z.Error("stop")
	assert.NotContains(t, buf.String(), "\x1b[")
}

// A sink that is not a terminal never gets colour, whatever the format.
func TestNew_PrettyOnNonTerminalHasNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	var buf bytes.Buffer
	r, err := New(Params{Level: "info", Format: FormatPretty, Sink: &buf})
	require.NoError(t, err)
	r.Zap.Error("stop")
	assert.Contains(t, buf.String(), "ERROR stop")
	assert.NotContains(t, buf.String(), "\x1b[")
}

func TestColorEnabled(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	assert.True(t, colorEnabled(true))
	assert.False(t, colorEnabled(false))

	t.Setenv("NO_COLOR", "1")
	assert.False(t, colorEnabled(true))
}

// A raw byte that is not UTF-8 (such as an 8-bit CSI) is escaped too.
func TestPretty_EscapesInvalidUTF8(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("a\x9b2J", zap.String("k", "v\x9b"), zap.Error(errors.New("e\x9b")))
	assert.Equal(t, `15:04:05.006 ERROR a\x9b2J k="v\x9b"`+"\n"+`  error: e\x9b`+"\n", buf.String())
}

// panicUnwrapError's Unwrap panics; its text is still shown.
type panicUnwrapError struct{}

func (panicUnwrapError) Error() string { return "outer" }
func (panicUnwrapError) Unwrap() error { panic("boom") }

// customError wraps a cause it does not quote.
type customError struct{ cause error }

func (customError) Error() string   { return "request failed" }
func (e customError) Unwrap() error { return e.cause }

func TestPretty_UnusualWrappers(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Error("stop", zap.Error(panicUnwrapError{}))
	z.Error("stop", zap.Error(customError{cause: errors.New("timeout")}))
	assert.Equal(t, "15:04:05.006 ERROR stop\n  error: outer\n"+
		"15:04:05.006 ERROR stop\n  error: request failed\n    ↳ timeout\n", buf.String())
}
