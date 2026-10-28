package log

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

var errCause = fmt.Errorf("sqlite: create state directory: %w", os.ErrPermission)

func failingApp(logger fxevent.Logger) *fx.App {
	return fx.New(
		fx.WithLogger(func() fxevent.Logger { return logger }),
		fx.Provide(func() (int, error) { return 0, errCause }),
		fx.Invoke(func(int) {}),
	)
}

// TestFxLogger_ErrorsReturned: the caller of a sub-graph logs the error it
// gets back, so fx logs nothing above debug and the caller's line names the
// root cause rather than dig's path to it.
func TestFxLogger_ErrorsReturned(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	z := zap.New(core)

	app := failingApp(FxLogger(z, ErrorsReturned()))
	require.Error(t, app.Err())
	Failure(z, "command failed", app.Err())

	require.Equal(t, 1, logs.Len(), "logged once: %v", logs.All())
	entry := logs.All()[0]
	assert.Equal(t, "command failed", entry.Message)
	assert.Equal(t, map[string]any{"error": errCause.Error(), "in": "int"}, entry.ContextMap())
}

func TestFxLogger_ErrorsReturnedAtDebug(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	z := zap.New(core)

	app := failingApp(FxLogger(z, ErrorsReturned()))
	Failure(z, "command failed", app.Err())

	assert.Equal(t, 0, logs.FilterLevelExact(zapcore.WarnLevel).Len())
	require.Equal(t, 1, logs.FilterLevelExact(zapcore.ErrorLevel).Len())
	assert.Equal(t, 1, logs.FilterLevelExact(zapcore.DebugLevel).FilterMessage("error returned").Len())
	invoke := logs.FilterLevelExact(zapcore.DebugLevel).FilterMessage("invoke failed").All()
	require.Len(t, invoke, 1)
	assert.Contains(t, invoke[0].ContextMap()["stack"], "\n", "fx's stack is still logged at debug")

	failed := logs.FilterLevelExact(zapcore.ErrorLevel).All()[0].ContextMap()
	assert.Equal(t, errCause.Error(), failed["error"])
	assert.Contains(t, failed["errorChain"], "could not build arguments", "the full chain follows at debug")
}

// TestFxLogger_Root: nothing else logs the root graph's failure, so fx's
// "start failed" is the one line, led by the root cause.
func TestFxLogger_Root(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)

	app := failingApp(FxLogger(zap.New(core)))
	require.Error(t, app.Start(context.Background()))

	require.Equal(t, 1, logs.Len(), "logged once: %v", logs.All())
	assert.Equal(t, "start failed", logs.All()[0].Message)
	assert.Equal(t, map[string]any{"error": errCause.Error(), "in": "int"}, logs.All()[0].ContextMap())
}

func TestFxLogger_RootStopFailureIsLogged(t *testing.T) {
	core, logs := observer.New(zapcore.InfoLevel)
	app := fx.New(
		fx.WithLogger(func() fxevent.Logger { return FxLogger(zap.New(core)) }),
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.StopHook(func() error { return errors.New("close: busy") }))
		}),
	)
	require.NoError(t, app.Start(context.Background()))
	require.Error(t, app.Stop(context.Background()))

	require.Equal(t, 1, logs.Len(), "logged once: %v", logs.All())
	assert.Equal(t, "stop failed", logs.All()[0].Message)
}

func TestFailure_PlainErrorHasNoChain(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)
	Failure(zap.New(core), "command failed", errCause)
	require.Equal(t, 1, logs.Len())
	assert.Equal(t, map[string]any{"error": errCause.Error()}, logs.All()[0].ContextMap())
}

type missingDep struct{}

const missingVerbose = "missing type:\n\t- *log.missingDep (did you mean to Provide it?)"

type needsIt struct{}

// TestFailure_Context: the line keeps what the caller added above dig and
// names what dig was building, or what needed a missing type.
func TestFailure_Context(t *testing.T) {
	built := fx.New(fx.NopLogger,
		fx.Provide(func() (*needsIt, error) { return nil, errCause }),
		fx.Invoke(func(*needsIt) {}),
	).Err()
	missing := fx.New(fx.NopLogger,
		fx.Provide(func(*missingDep) *needsIt { return nil }),
		fx.Invoke(func(*needsIt) {}),
	).Err()
	invoked := fx.New(fx.NopLogger, fx.Invoke(func(*missingDep) {})).Err()
	group := fx.New(fx.NopLogger,
		fx.Provide(fx.Annotate(func() (int, error) { return 0, errCause }, fx.ResultTags(`group:"n"`))),
		fx.Invoke(fx.Annotate(func([]int) {}, fx.ParamTags(`group:"n"`))),
	).Err()

	for name, tc := range map[string]struct {
		err  error
		want map[string]any
	}{
		"constructor failed": {built, map[string]any{"error": errCause.Error(), "in": "*log.needsIt"}},
		"wrapped":            {fmt.Errorf("migrate: %w", built), map[string]any{"error": "migrate: " + errCause.Error(), "in": "*log.needsIt"}},
		// dig's own hint stays as errorVerbose.
		"missing type": {missing, map[string]any{
			"error": "missing type: *log.missingDep", "in": "*log.needsIt", "errorVerbose": missingVerbose,
		}},
		"invoke missing type": {invoked, map[string]any{
			"error": "missing type: *log.missingDep", "in": "log.TestFailure_Context.func5", "errorVerbose": missingVerbose,
		}},
		"value group": {group, map[string]any{"error": errCause.Error(), "in": `int[group="n"]`}},
		"not dig":     {fmt.Errorf("migrate: %w", errCause), map[string]any{"error": "migrate: " + errCause.Error()}},
	} {
		t.Run(name, func(t *testing.T) {
			core, logs := observer.New(zapcore.InfoLevel)
			Failure(zap.New(core), "command failed", tc.err)
			require.Equal(t, 1, logs.Len())
			assert.Equal(t, tc.want, logs.All()[0].ContextMap())
		})
	}
}

// listError has a slice as its dynamic type, so == on it panics.
type listError []string

func (e listError) Error() string { return strings.Join(e, ",") }

// TestFailure_UncomparableAndCyclicErrors: an error that == would panic on, or
// whose chain loops, is still logged.
func TestFailure_UncomparableAndCyclicErrors(t *testing.T) {
	for name, err := range map[string]error{
		"slice":         listError{"x"},
		"slice wrapped": fmt.Errorf("ctx: %w", listError{"x"}),
		"slice loop":    sliceError{"x"},
		"self":          &loopError{msg: "loop"},
	} {
		t.Run(name, func(t *testing.T) {
			core, logs := observer.New(zapcore.DebugLevel)
			Failure(zap.New(core), "command failed", err)
			require.Equal(t, 1, logs.Len())
			assert.Equal(t, map[string]any{"error": err.Error()}, logs.All()[0].ContextMap())
		})
	}
}

// TestFailed_EveryErrorEvent: every fx event type with an error field counts
// as a failure when it is set, found from fxevent's source so a type added by
// an fx upgrade is not missed.
func TestFailed_EveryErrorEvent(t *testing.T) {
	events := map[string]fxevent.Event{}
	for _, e := range []fxevent.Event{
		&fxevent.OnStartExecuting{}, &fxevent.OnStartExecuted{}, &fxevent.OnStopExecuting{},
		&fxevent.OnStopExecuted{}, &fxevent.Supplied{}, &fxevent.Provided{},
		&fxevent.Replaced{}, &fxevent.Decorated{}, &fxevent.BeforeRun{}, &fxevent.Run{},
		&fxevent.Invoking{}, &fxevent.Invoked{}, &fxevent.Stopping{}, &fxevent.Stopped{},
		&fxevent.RollingBack{}, &fxevent.RolledBack{}, &fxevent.Started{}, &fxevent.LoggerInitialized{},
	} {
		events[reflect.TypeOf(e).Elem().Name()] = e
	}

	pkg, err := build.Import("go.uber.org/fx/fxevent", "", 0)
	require.NoError(t, err)
	fset := token.NewFileSet()
	withErr := 0
	for _, name := range pkg.GoFiles {
		f, err := parser.ParseFile(fset, filepath.Join(pkg.Dir, name), nil, 0)
		require.NoError(t, err)
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts := spec.(*ast.TypeSpec)
				st, ok := ts.Type.(*ast.StructType)
				if !ok || !ts.Name.IsExported() || !hasErrorField(st) {
					continue
				}
				e, ok := events[ts.Name.Name]
				if !assert.True(t, ok, "fxevent.%s carries an error: add it here", ts.Name.Name) {
					continue
				}
				withErr++
				assert.False(t, failed(e), ts.Name.Name)
				v := reflect.ValueOf(e).Elem()
				for i := range v.NumField() {
					if v.Field(i).Type() == errorType {
						v.Field(i).Set(reflect.ValueOf(errCause))
					}
				}
				assert.True(t, failed(e), ts.Name.Name)
			}
		}
	}
	assert.GreaterOrEqual(t, withErr, 13, "found fxevent's error events")
	assert.False(t, failed(&fxevent.Invoking{}))
}

func hasErrorField(st *ast.StructType) bool {
	for _, f := range st.Fields.List {
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "error" {
			return true
		}
	}
	return false
}

// TestBootLogger_FailsBeforeLogger: a graph that fails before the zap logger
// exists (an invalid LOG_LEVEL) prints one line, not fx's console logger's
// provide events and dig chain.
func TestBootLogger_FailsBeforeLogger(t *testing.T) {
	var out bytes.Buffer
	boot := NewBootLogger(&out, "tempogate")
	app := fx.New(
		fx.WithLogger(func() fxevent.Logger { return boot }),
		fx.Provide(func() (*zap.Logger, error) { return nil, errors.New("invalid config: LOG_LEVEL \x1b") }),
		fx.Invoke(boot.Use),
	)
	require.Error(t, app.Start(context.Background()))
	assert.Equal(t, "tempogate: invalid config: LOG_LEVEL \\x1b\n", out.String())
}

// TestBootLogger_PassesEventsOn: once Use has the logger, held and later
// events reach FxLogger, and nothing goes to the boot writer.
func TestBootLogger_PassesEventsOn(t *testing.T) {
	var out bytes.Buffer
	core, logs := observer.New(zapcore.DebugLevel)
	boot := NewBootLogger(&out, "tempogate")

	boot.LogEvent(&fxevent.Provided{ConstructorName: "held", Err: errCause})
	boot.Use(zap.New(core))
	boot.LogEvent(&fxevent.Started{Err: errCause})

	assert.Empty(t, out.String())
	require.Equal(t, 2, logs.Len(), "%v", logs.All())
	assert.Equal(t, zapcore.DebugLevel, logs.All()[0].Level)
	assert.Equal(t, "error encountered while applying options", logs.All()[0].Message)
	assert.Equal(t, "start failed", logs.All()[1].Message)
}
