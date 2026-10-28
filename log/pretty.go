package log

import (
	"reflect"
	"slices"
	"strconv"
	"strings"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// The pretty format is for a person at a terminal: a short header line with
// the scalar fields inline as key=value, then each error, multi-line string
// and stack as an indented block under it. zap's console encoder would print
// an error's %+v as errorVerbose and a stack as one string full of \n\t
// escapes, which buries the cause a failed startup is about.
//
// It is for development, so it favours readable output and code over
// allocation (objects and reflected values go through a map encoder and
// encoding/json, and each error in a chain costs its Error() string); json is
// the format for production.
//
// Everything it writes that is not its own colour codes goes through
// escapeControls or strconv.Quote, so a logged value cannot move the cursor,
// clear the screen or start a line that looks like another entry.

const (
	blockIndent = "  "
	causeMarker = "↳ "
	// maxErrorNodes bounds the errors visited in one field, so a cyclic or
	// very deep chain is cut short instead of overflowing the stack.
	maxErrorNodes = 64
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
		EncodeName:       encodeName,
		ConsoleSeparator: " ",
	})}
}

func encodeName(name string, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString("[" + escapeControls(name, false) + "]")
}

func (e *prettyEncoder) Clone() zapcore.Encoder {
	return &prettyEncoder{Encoder: e.Encoder.Clone()}
}

func (e *prettyEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	stack := ent.Stack
	ent.Stack = ""
	ent.Message = escapeControls(ent.Message, false)
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
		case f.Type == zapcore.ErrorType,
			f.Type == zapcore.StringType && strings.Contains(f.String, "\n"),
			errorList(f) != nil:
			f.Key = namespace + f.Key
			blocks = append(blocks, f)
		default:
			appendInline(buf, namespace, f)
		}
	}
	buf.AppendString(zapcore.DefaultLineEnding)

	for _, f := range blocks {
		buf.AppendString(blockIndent + escapeControls(f.Key, false) + ":")
		w := &errorWriter{buf: buf, base: blockIndent, budget: maxErrorNodes}
		switch errs := errorList(f); {
		case f.Type == zapcore.ErrorType:
			if err, ok := f.Interface.(error); ok {
				w.write(err, 0)
			}
		case errs != nil:
			w.base += blockIndent
			for i, err := range errs {
				if err != nil {
					buf.AppendString(zapcore.DefaultLineEnding + w.base + "[" + strconv.Itoa(i) + "]")
					w.write(err, 0)
				}
			}
		default:
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

// errorList returns the errors of a zap.Errors field, or nil for any other.
// zap.Errors is an array of an unexported []error type, so it is found by
// shape.
func errorList(f zapcore.Field) []error {
	if f.Type != zapcore.ArrayMarshalerType {
		return nil
	}
	v := reflect.ValueOf(f.Interface)
	if v.Kind() != reflect.Slice || v.Type().Elem() != errorType {
		return nil
	}
	errs := make([]error, v.Len())
	for i := range errs {
		errs[i], _ = v.Index(i).Interface().(error)
	}
	return errs
}

// appendText writes s on the lines below the current one, each indented, so a
// stack trace keeps its real line breaks.
func appendText(buf *buffer.Buffer, s string) {
	pad := blockIndent + blockIndent
	for line := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		buf.AppendString(zapcore.DefaultLineEnding + pad + escapeControls(line, false))
	}
}

var prettyBufs = buffer.NewPool()

// errorWriter writes an error's chain one level per line, each level indented
// under the one it wraps and showing only its own text.
type errorWriter struct {
	buf *buffer.Buffer
	// base is the indent of the line the chain starts on.
	base string
	// budget is how many more errors may be visited; once it runs out, a
	// marker ends the chain.
	budget int
	// path holds the comparable errors from the top of the chain down to the
	// one being written, to spot a cycle.
	path []error
}

// write writes err at level. Level 0 continues the current line; deeper
// levels each start a line, indented under the level above. An error with no
// text of its own (a join) puts its causes at its level, as siblings.
func (w *errorWriter) write(err error, level int) {
	if w.budget <= 0 {
		if w.budget == 0 {
			w.marker(level, "truncated")
			w.budget--
		}
		return
	}
	w.budget--
	causes, cycle := w.notOnPath(causesOf(err))
	own, causes := splitOwn(errorText(err), causes)
	next := level
	switch {
	case own != "":
		if level == 0 {
			w.buf.AppendByte(' ')
		} else {
			w.newline(level, causeMarker)
		}
		// A multi-line message continues under its first line.
		w.buf.AppendString(strings.ReplaceAll(escapeControls(own, true), "\n",
			zapcore.DefaultLineEnding+w.base+strings.Repeat(blockIndent, level+1)))
		next = level + 1
	case level == 0 && len(causes)+len(cycle) > 1:
		next = 1
	}
	if isComparable(err) {
		w.path = append(w.path, err)
		defer func() { w.path = w.path[:len(w.path)-1] }()
	}
	for _, c := range causes {
		w.write(c, next)
	}
	if len(cycle) > 0 {
		w.marker(next, "cycle")
	}
}

func (w *errorWriter) newline(level int, marker string) {
	w.buf.AppendString(zapcore.DefaultLineEnding + w.base + strings.Repeat(blockIndent, level) + marker)
}

func (w *errorWriter) marker(level int, what string) {
	w.newline(max(level, 1), causeMarker+"… ("+what+")")
}

// notOnPath splits causes into those not already on the path down to them
// and those that are, which would loop.
func (w *errorWriter) notOnPath(causes []error) (fresh, cycle []error) {
	for _, c := range causes {
		if isComparable(c) && slices.Contains(w.path, c) {
			cycle = append(cycle, c)
		} else {
			fresh = append(fresh, c)
		}
	}
	return fresh, cycle
}

// isComparable reports whether err can be compared with ==, which panics for
// an error whose dynamic type is (or holds) a slice, map or func.
func isComparable(err error) bool {
	return reflect.ValueOf(err).Comparable()
}

// unwrap returns err's own message, without the text of the causes it wraps,
// and those causes.
func unwrap(err error) (own string, causes []error) {
	return splitOwn(errorText(err), causesOf(err))
}

// causesOf returns the errors err wraps. It never formats err with %+v: that
// is what produces errorVerbose, and some errors (dig's) put file paths and
// stacks there.
func causesOf(err error) (causes []error) {
	defer func() {
		if recover() != nil {
			causes = nil
		}
	}()
	switch e := err.(type) {
	case interface{ Errors() []error }: // go.uber.org/multierr
		causes = e.Errors()
	case interface{ Unwrap() []error }: // errors.Join, fmt.Errorf with several %w
		causes = e.Unwrap()
	case interface{ Unwrap() error }:
		causes = []error{e.Unwrap()}
	}
	return slices.DeleteFunc(slices.Clone(causes), func(c error) bool { return c == nil })
}

// splitOwn returns the part of msg that is err's own, and the causes to show
// under it. Only the separator left after cutting a cause's text is trimmed;
// an error's own text is never otherwise changed.
func splitOwn(msg string, causes []error) (own string, shown []error) {
	// The usual wrapper is "context: cause".
	if len(causes) == 1 {
		if cm := errorText(causes[0]); cm != "" && strings.HasSuffix(msg, cm) {
			return trimSeparator(strings.TrimSuffix(msg, cm)), causes
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
	if len(causes) > 0 && strings.TrimLeft(rest, " \t\n:;,") == "" {
		return "", causes
	}
	// Anything else quotes its causes inside its own text, as in
	// fmt.Errorf("%w: %s", ErrSentinel, detail): splitting that would print
	// the detail above the sentence it completes, so it stays whole.
	return msg, unquoted
}

// trimSeparator removes the separator a wrapper puts before its cause's text:
// trailing space, then one ':', ';' or ','.
func trimSeparator(s string) string {
	s = strings.TrimRight(s, " \t\n")
	if n := len(s); n > 0 && strings.IndexByte(":;,", s[n-1]) >= 0 {
		s = s[:n-1]
	}
	return s
}

// errorText is err.Error(), recovering from a panicking implementation. Like
// zap, a nil pointer that panics reads as <nil>.
func errorText(err error) string {
	msg, _ := recoverText(err, func() string { return err.Error() })
	return msg
}
