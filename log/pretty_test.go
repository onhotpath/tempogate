package log

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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
	z, buf := prettyLogger(false)
	var err *panicError
	z.Error("stop", zap.Error(err))
	assert.Equal(t, "15:04:05.006 ERROR stop\n  error: PANIC=boom\n", buf.String())
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
