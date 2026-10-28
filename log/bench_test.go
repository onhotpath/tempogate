package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// The benchmarks compare each format against zap's own encoders on the same
// calls. Sub-benchmark names are key=value, so benchstat can put the
// encoders side by side:
//
//	go test -run '^$' -bench 'BenchmarkLog$' -count 10 ./log/ > new.txt
//	go run golang.org/x/perf/cmd/benchstat@latest -row /case -col /enc new.txt

var benchSink = zapcore.AddSync(io.Discard)

type benchEncoder struct {
	name string
	core func(zapcore.LevelEnabler) zapcore.Core
}

var benchEncoders = []benchEncoder{
	// The reference: zap's production JSON encoder.
	{"baseline-zap-prod", func(l zapcore.LevelEnabler) zapcore.Core {
		return zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), benchSink, l)
	}},
	// tempogate's line format before LOG_FORMAT.
	{"baseline-zap-dev-console", func(l zapcore.LevelEnabler) zapcore.Core {
		return zapcore.NewCore(zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig()), benchSink, l)
	}},
	{"json", func(l zapcore.LevelEnabler) zapcore.Core { return newCore(FormatJSON, false, benchSink, l) }},
	{"pretty", func(l zapcore.LevelEnabler) zapcore.Core { return newCore(FormatPretty, false, benchSink, l) }},
	{"pretty-color", func(l zapcore.LevelEnabler) zapcore.Core { return newCore(FormatPretty, true, benchSink, l) }},
}

var (
	benchTime       = fixedClock{}.Now()
	errBenchDial    = errors.New("dial tcp 10.0.0.7:5432: connect: connection refused")
	errBenchWrapped = fmt.Errorf("open store: %w", errBenchDial)
	errBenchJoin    = errors.Join(
		errors.New("issuer: must be an https URL"),
		fmt.Errorf("signing key: %w", os.ErrNotExist),
		errors.New("listen: address already in use"),
	)
	errBenchDeep = digLikeChain(8)
	benchStack   = "main.run\n\t/src/tempogate/cmd/tempogate/main.go:42\n" +
		"go.uber.org/fx.(*App).Start\n\t/go/pkg/mod/go.uber.org/fx@v1.24.0/app.go:671\n" +
		"go.uber.org/fx.Invoke\n\t/go/pkg/mod/go.uber.org/fx@v1.24.0/invoke.go:108\n" +
		"github.com/onhotpath/tempogate/cmd/servercmd.Run\n\t/src/tempogate/cmd/servercmd/server.go:88\n" +
		"runtime.main\n\t/usr/local/go/src/runtime/proc.go:283\n"
)

// digLikeError is what a dig error looks like to a logger: its text holds
// its cause's, and its %+v adds a file path per level.
type digLikeError struct {
	msg   string
	cause error
}

func (e *digLikeError) Error() string { return e.msg + ": " + e.cause.Error() }
func (e *digLikeError) Unwrap() error { return e.cause }
func (e *digLikeError) Format(s fmt.State, verb rune) {
	if verb == 'v' && s.Flag('+') {
		_, _ = fmt.Fprintf(s, "%s:\n\t/go/pkg/mod/go.uber.org/dig@v1.19.0/container.go:%d:\n%+v", e.msg, len(e.msg), e.cause)
		return
	}
	_, _ = io.WriteString(s, e.Error())
}

func digLikeChain(depth int) error {
	err := fmt.Errorf("sqlite: create state directory: %w", os.ErrPermission)
	for i := depth - 1; i > 0; i-- {
		err = &digLikeError{msg: fmt.Sprintf("failed to build *pkg%d.Type%d", i, i), cause: err}
	}
	return &digLikeError{msg: `could not build arguments for function "github.com/onhotpath/tempogate/cmd/servercmd".run`, cause: err}
}

type benchClient struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Public bool     `json:"public"`
	Scopes []string `json:"scopes"`
}

type benchCase struct {
	name string
	// setup returns one call to measure, logging through core at info.
	setup func(core zapcore.Core) func()
}

func benchZap(core zapcore.Core) *zap.Logger { return zap.New(core, zap.WithClock(fixedClock{})) }

// logScalarFields logs the shape of the access log line (cmd/servercmd/accesslog.go).
func logScalarFields(z *zap.Logger, lvl zapcore.Level) {
	z.Log(lvl, "http request",
		zap.String("method", "GET"),
		zap.String("path", "/oauth/token"),
		zap.Int("status", 200),
		zap.Duration("duration", 1234567*time.Nanosecond),
		zap.Bool("cached", false),
		zap.Time("at", benchTime),
		zap.Strings("scopes", []string{"openid", "profile"}),
	)
}

var benchCases = []benchCase{
	{"message", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { z.Info("server listening") }
	}},
	{"scalar-fields", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { logScalarFields(z, zapcore.InfoLevel) }
	}},
	{"with-fields", func(core zapcore.Core) func() {
		z := benchZap(core).With(
			zap.String("component", "oauth"),
			zap.String("request_id", "01JB3S9K6Q0W5X8V2M4N7P1R3T"),
			zap.Int("attempt", 1),
		)
		return func() { z.Info("token issued", zap.String("client", "web"), zap.Int("status", 200)) }
	}},
	{"wrapped-error", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { z.Info("store unavailable", zap.Error(errBenchWrapped)) }
	}},
	{"dig-chain-8", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { z.Info("start failed", zap.Error(errBenchDeep)) }
	}},
	{"join-3", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { z.Info("invalid config", zap.Error(errBenchJoin)) }
	}},
	{"stack-string", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() {
			z.Info("invoke failed", zap.String("function", "servercmd.Run"), zap.String("stack", benchStack))
		}
	}},
	{"any-struct-map", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() {
			z.Info("client registered",
				zap.Any("client", benchClient{ID: "c1", Name: "web", Public: true, Scopes: []string{"openid"}}),
				zap.Any("labels", map[string]string{"team": "auth", "tier": "1", "env": "dev"}),
			)
		}
	}},
	{"disabled-debug", func(core zapcore.Core) func() {
		z := benchZap(core)
		return func() { logScalarFields(z, zapcore.DebugLevel) }
	}},
	// slog stamps the record with time.Now; zapslog has no clock option.
	{"slog-attrs-group", func(core zapcore.Core) func() {
		l := slog.New(zapslog.NewHandler(core, zapslog.WithCaller(true)))
		ctx := context.Background()
		return func() {
			l.LogAttrs(ctx, slog.LevelInfo, "http request",
				slog.String("method", "GET"),
				slog.Int("status", 200),
				slog.Duration("duration", 1234567*time.Nanosecond),
				slog.Group("client", slog.String("id", "c1"), slog.Bool("public", true)),
			)
		}
	}},
}

func BenchmarkLog(b *testing.B) {
	for _, c := range benchCases {
		for _, e := range benchEncoders {
			b.Run("case="+c.name+"/enc="+e.name, func(b *testing.B) {
				call := c.setup(e.core(zapcore.InfoLevel))
				b.ReportAllocs()
				for b.Loop() {
					call()
				}
			})
		}
	}
}

func BenchmarkLogParallel(b *testing.B) {
	for _, c := range benchCases {
		if c.name != "scalar-fields" && c.name != "with-fields" {
			continue
		}
		for _, e := range benchEncoders {
			b.Run("case="+c.name+"/enc="+e.name, func(b *testing.B) {
				call := c.setup(e.core(zapcore.InfoLevel))
				b.ReportAllocs()
				b.RunParallel(func(pb *testing.PB) {
					for pb.Next() {
						call()
					}
				})
			})
		}
	}
}

type benchStore struct{}

// benchDigError is a real fx startup error: a constructor failed under an
// invoke.
func benchDigError(b *testing.B) error {
	b.Helper()
	err := fx.New(fx.NopLogger,
		fx.Provide(func() (*benchStore, error) {
			return nil, fmt.Errorf("sqlite: create state directory: %w", os.ErrPermission)
		}),
		fx.Invoke(func(*benchStore) {}),
	).Err()
	if err == nil {
		b.Fatal("want a dig error")
	}
	return err
}

func BenchmarkFxLogger(b *testing.B) {
	digErr := benchDigError(b)
	ok := &fxevent.Provided{
		ConstructorName: "github.com/onhotpath/tempogate/store.New()",
		OutputTypeNames: []string{"*store.Store"},
	}
	invokeFailed := &fxevent.Invoked{FunctionName: "servercmd.Run", Trace: benchStack, Err: digErr}
	startFailed := &fxevent.Started{Err: digErr}

	// Before Use, events are held, or a start failure is written as one line.
	b.Run("case=held-ok", func(b *testing.B) {
		bl := NewBootLogger(io.Discard, "tempogate")
		b.ReportAllocs()
		for b.Loop() {
			bl.LogEvent(ok)
			bl.held = bl.held[:0]
		}
	})
	b.Run("case=held-start-failed", func(b *testing.B) {
		bl := NewBootLogger(io.Discard, "tempogate")
		b.ReportAllocs()
		for b.Loop() {
			bl.LogEvent(startFailed)
		}
	})

	for _, e := range benchEncoders[2:] {
		for _, c := range []struct {
			name  string
			level zapcore.Level
			event fxevent.Event
		}{
			{"attached-ok", zapcore.InfoLevel, ok},
			{"attached-invoke-failed", zapcore.InfoLevel, invokeFailed},
			{"attached-invoke-failed-at-debug", zapcore.DebugLevel, invokeFailed},
			{"attached-start-failed", zapcore.InfoLevel, startFailed},
		} {
			b.Run("case="+c.name+"/enc="+e.name, func(b *testing.B) {
				bl := NewBootLogger(io.Discard, "tempogate")
				bl.Use(benchZap(e.core(c.level)))
				b.ReportAllocs()
				for b.Loop() {
					bl.LogEvent(c.event)
				}
			})
		}
	}
}

func BenchmarkFailure(b *testing.B) {
	digErr := benchDigError(b)
	for _, e := range benchEncoders[2:] {
		for _, c := range []struct {
			name  string
			level zapcore.Level
			err   error
		}{
			{"plain", zapcore.InfoLevel, errBenchWrapped},
			{"dig", zapcore.InfoLevel, digErr},
			{"dig-wrapped", zapcore.InfoLevel, fmt.Errorf("migrate: %w", digErr)},
			{"dig-at-debug", zapcore.DebugLevel, digErr},
		} {
			b.Run("case="+c.name+"/enc="+e.name, func(b *testing.B) {
				z := benchZap(e.core(c.level))
				b.ReportAllocs()
				for b.Loop() {
					Failure(z, "start failed", c.err)
				}
			})
		}
	}
}
