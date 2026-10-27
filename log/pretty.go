package log

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// The pretty format is for a person at a terminal: a short header line with
// the scalar fields inline as key=value, then each error, multi-line string
// and stack as an indented block under it. zap's console encoder would print
// an error's %+v as errorVerbose and a stack as one string full of \n\t
// escapes, which buries the cause a failed startup is about.

const (
	blockIndent = "  "
	causeMarker = "↳ "
	// maxErrorDepth bounds the walk down an error chain, in case an Unwrap
	// cycles.
	maxErrorDepth = 32
)

// prettyCore keeps With fields until Write, so the encoder still sees each
// field's type: the core zap builds encodes With fields into the encoder at
// once, which turns an error into plain strings before it can be rendered.
type prettyCore struct {
	zapcore.Core
	fields []zapcore.Field
}

func (c *prettyCore) With(fields []zapcore.Field) zapcore.Core {
	return &prettyCore{Core: c.Core, fields: append(slices.Clip(c.fields), fields...)}
}

func (c *prettyCore) Check(ent zapcore.Entry, ce *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(ent.Level) {
		return ce.AddCore(ent, c)
	}
	return ce
}

func (c *prettyCore) Write(ent zapcore.Entry, fields []zapcore.Field) error {
	return c.Core.Write(ent, append(slices.Clip(c.fields), fields...))
}

// prettyEncoder uses zap's console encoder for the header (time, level,
// logger name, caller, message) and renders every field itself.
type prettyEncoder struct {
	zapcore.Encoder
}

func newPrettyEncoder(color bool) *prettyEncoder {
	level := zapcore.CapitalLevelEncoder
	if color {
		level = zapcore.CapitalColorLevelEncoder
	}
	return &prettyEncoder{Encoder: zapcore.NewConsoleEncoder(zapcore.EncoderConfig{
		TimeKey:          "T",
		LevelKey:         "L",
		NameKey:          "N",
		CallerKey:        "C",
		FunctionKey:      zapcore.OmitKey,
		MessageKey:       "M",
		StacktraceKey:    zapcore.OmitKey,
		LineEnding:       zapcore.DefaultLineEnding,
		EncodeLevel:      level,
		EncodeTime:       zapcore.TimeEncoderOfLayout("15:04:05.000"),
		EncodeDuration:   zapcore.StringDurationEncoder,
		EncodeCaller:     zapcore.ShortCallerEncoder,
		EncodeName:       func(name string, enc zapcore.PrimitiveArrayEncoder) { enc.AppendString("[" + name + "]") },
		ConsoleSeparator: " ",
	})}
}

func (e *prettyEncoder) Clone() zapcore.Encoder {
	return &prettyEncoder{Encoder: e.Encoder.Clone()}
}

func (e *prettyEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	stack := ent.Stack
	ent.Stack = ""
	buf, err := e.Encoder.EncodeEntry(ent, nil)
	if err != nil {
		return nil, err
	}
	buf.TrimNewline()

	var blocks []zapcore.Field
	namespace := ""
	for _, f := range fields {
		switch {
		case f.Type == zapcore.NamespaceType:
			namespace += f.Key + "."
		case f.Type == zapcore.ErrorType, f.Type == zapcore.StringType && strings.Contains(f.String, "\n"):
			f.Key = namespace + f.Key
			blocks = append(blocks, f)
		default:
			appendInline(buf, namespace, f)
		}
	}
	buf.AppendString(zapcore.DefaultLineEnding)

	for _, f := range blocks {
		buf.AppendString(blockIndent + f.Key + ":")
		if err, ok := f.Interface.(error); ok && f.Type == zapcore.ErrorType {
			appendError(buf, err, 0)
		} else {
			appendText(buf, f.String)
		}
		buf.AppendString(zapcore.DefaultLineEnding)
	}
	if stack != "" {
		buf.AppendString(blockIndent + "stacktrace:")
		appendText(buf, stack)
		buf.AppendString(zapcore.DefaultLineEnding)
	}
	return buf, nil
}

// appendInline writes f as " key=value" pairs. A field can expand to several
// keys (zap.Inline), so it goes through a map encoder rather than its type.
func appendInline(buf *buffer.Buffer, namespace string, f zapcore.Field) {
	m := zapcore.NewMapObjectEncoder()
	f.AddTo(m)
	keys := make([]string, 0, len(m.Fields))
	for k := range m.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		buf.AppendString(" " + namespace + k + "=")
		appendValue(buf, m.Fields[k])
	}
}

func appendValue(buf *buffer.Buffer, v any) {
	switch v := v.(type) {
	case string:
		appendString(buf, v)
	case bool:
		buf.AppendBool(v)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64, uintptr, float32, float64:
		_, _ = fmt.Fprint(buf, v)
	case time.Duration:
		buf.AppendString(v.String())
	case time.Time:
		buf.AppendString(v.Format(time.RFC3339Nano))
	default:
		// Objects, arrays and reflected values stay inline as JSON.
		b, err := json.Marshal(v)
		if err != nil {
			appendString(buf, fmt.Sprint(v))
			return
		}
		_, _ = buf.Write(b)
	}
}

// appendString quotes s only when it would not read back as one token.
func appendString(buf *buffer.Buffer, s string) {
	if s == "" || strings.IndexFunc(s, func(r rune) bool {
		return r == '=' || r == '"' || unicode.IsSpace(r) || !unicode.IsPrint(r)
	}) >= 0 {
		buf.AppendString(strconv.Quote(s))
		return
	}
	buf.AppendString(s)
}

// appendText writes s on the lines below the current one, each indented, so a
// stack trace keeps its real line breaks.
func appendText(buf *buffer.Buffer, s string) {
	pad := blockIndent + blockIndent
	for line := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		buf.AppendString(zapcore.DefaultLineEnding + pad + line)
	}
}

// appendError writes err's chain one level per line, each level indented
// under the one it wraps and showing only its own text. depth 0 continues the
// "key:" line; an error with no text of its own (a join) puts its causes at
// its depth, as siblings, below the "key:" line.
func appendError(buf *buffer.Buffer, err error, depth int) {
	if depth >= maxErrorDepth {
		return
	}
	own, causes := unwrap(err)
	next := depth
	switch {
	case own != "":
		if depth == 0 {
			buf.AppendByte(' ')
		} else {
			buf.AppendString(zapcore.DefaultLineEnding + strings.Repeat(blockIndent, depth+1) + causeMarker)
		}
		// A multi-line message continues under its first line.
		buf.AppendString(strings.ReplaceAll(own, "\n", zapcore.DefaultLineEnding+strings.Repeat(blockIndent, depth+2)))
		next = depth + 1
	case depth == 0 && len(causes) > 1:
		next = 1
	}
	for _, c := range causes {
		appendError(buf, c, next)
	}
}

// unwrap returns err's own message, without the text of the causes it wraps,
// and those causes. It never formats err with %+v: that is what produces
// errorVerbose, and some errors (dig's) put file paths and stacks there.
func unwrap(err error) (own string, causes []error) {
	defer func() {
		if r := recover(); r != nil {
			own, causes = fmt.Sprintf("PANIC=%v", r), nil
		}
	}()
	msg := errorText(err)
	switch e := err.(type) {
	case interface{ Errors() []error }: // go.uber.org/multierr
		causes = e.Errors()
	case interface{ Unwrap() []error }: // errors.Join, fmt.Errorf with several %w
		causes = e.Unwrap()
	case interface{ Unwrap() error }:
		causes = []error{e.Unwrap()}
	}
	causes = slices.DeleteFunc(causes, func(c error) bool { return c == nil })

	// The usual wrapper is "context: cause".
	if len(causes) == 1 {
		if cm := errorText(causes[0]); cm != "" && strings.HasSuffix(msg, cm) {
			return trimJoiners(strings.TrimSuffix(msg, cm)), causes
		}
	}
	rest := msg
	var unquoted []error
	for _, c := range causes {
		if cm := errorText(c); cm != "" && strings.Contains(rest, cm) {
			rest = strings.Replace(rest, cm, "", 1)
		} else {
			unquoted = append(unquoted, c)
		}
	}
	// A join's text is only its causes'.
	if trimJoiners(rest) == "" {
		return "", causes
	}
	// Anything else quotes its causes inside its own text, as in
	// fmt.Errorf("%w: %s", ErrSentinel, detail): splitting that would print
	// the detail above the sentence it completes, so it stays whole.
	return trimJoiners(msg), unquoted
}

func trimJoiners(s string) string { return strings.Trim(s, " \t\n:;,-") }

// errorText is err.Error(), recovering from a panicking implementation (such
// as a nil pointer with a value-receiver method).
func errorText(err error) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg = fmt.Sprintf("PANIC=%v", r)
		}
	}()
	return err.Error()
}
