package log

import (
	"context"
	"errors"
	"fmt"
	"os"
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
	assert.Equal(t, map[string]any{"error": errCause.Error()}, entry.ContextMap())
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
	assert.Equal(t, map[string]any{"error": errCause.Error()}, logs.All()[0].ContextMap())
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
