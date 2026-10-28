// Package log provides a zap-backed logger and a slog handler that share the
// same core, so callers can pick either API and still emit through one sink.
package log

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/mattn/go-isatty"
	"go.uber.org/fx"
	"go.uber.org/zap"
	"go.uber.org/zap/exp/zapslog"
	"go.uber.org/zap/zapcore"
)

// Level is a string log level (e.g. "debug", "info", "warn", "error").
// Defined here so config can expose it without importing zap.
type Level string

// Format is the line format (LOG_FORMAT).
type Format string

const (
	// FormatAuto is FormatPretty on a terminal and FormatJSON otherwise.
	FormatAuto Format = "auto"
	// FormatJSON is one JSON object per line, for log collectors.
	FormatJSON Format = "json"
	// FormatPretty is a human-readable line per entry, with errors and
	// stacks rendered as indented blocks under it.
	FormatPretty Format = "pretty"
)

// ParseFormat returns the Format s names, ignoring case and surrounding
// space, or an error naming the valid ones. Empty is FormatAuto.
func ParseFormat(s string) (Format, error) {
	switch f := Format(strings.ToLower(strings.TrimSpace(s))); f {
	case "":
		return FormatAuto, nil
	case FormatAuto, FormatJSON, FormatPretty:
		return f, nil
	default:
		return "", fmt.Errorf("LOG_FORMAT must be %q, %q or %q, got %q", FormatAuto, FormatJSON, FormatPretty, s)
	}
}

// ParseLevel returns the Level s names, ignoring case and surrounding space,
// or an error naming the valid ones. Empty is info, as in zap.
func ParseLevel(s string) (Level, error) {
	lvl, err := parseLevel(s)
	if err != nil {
		return "", err
	}
	return Level(lvl.String()), nil
}

func parseLevel(s string) (zapcore.Level, error) {
	lvl, err := zapcore.ParseLevel(strings.ToLower(strings.TrimSpace(s)))
	if err != nil {
		return lvl, fmt.Errorf("LOG_LEVEL must be %q, %q, %q or %q, got %q", "debug", "info", "warn", "error", s)
	}
	return lvl, nil
}

type Params struct {
	fx.In

	Level Level
	// Format is the line format; empty means FormatAuto.
	Format Format    `optional:"true"`
	Sink   io.Writer `optional:"true"`
}

type Result struct {
	fx.Out

	Zap  *zap.Logger
	Slog *slog.Logger
}

func New(p Params) (Result, error) {
	lvl, err := parseLevel(string(p.Level))
	if err != nil {
		return Result{}, err
	}
	format, err := ParseFormat(string(p.Format))
	if err != nil {
		return Result{}, err
	}

	sink := p.Sink
	if sink == nil {
		sink = os.Stdout
	}
	tty := isTerminal(sink)

	core := newCore(resolve(format, tty), colorEnabled(tty), zapcore.Lock(zapcore.AddSync(sink)), lvl)

	return Result{
		Zap:  zap.New(core),
		Slog: slog.New(zapslog.NewHandler(core, zapslog.WithCaller(true))),
	}, nil
}

func newCore(format Format, color bool, out zapcore.WriteSyncer, lvl zapcore.LevelEnabler) zapcore.Core {
	if format == FormatPretty {
		return newPrettyCore(newPrettyEncoder(color), out, lvl)
	}
	return zapcore.NewCore(zapcore.NewJSONEncoder(jsonEncoderConfig()), out, lvl)
}

func jsonEncoderConfig() zapcore.EncoderConfig {
	return zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     encodeTime,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}
}

func resolve(f Format, tty bool) Format {
	if f != FormatAuto {
		return f
	}
	if tty {
		return FormatPretty
	}
	return FormatJSON
}

// isTerminal reports whether w is a terminal. Anything but an *os.File (an
// injected buffer in tests) is not.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	return ok && (isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd()))
}

// colorEnabled follows https://no-color.org: a non-empty NO_COLOR turns
// colour off even on a terminal.
func colorEnabled(tty bool) bool {
	return tty && os.Getenv("NO_COLOR") == ""
}
