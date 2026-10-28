package log

import (
	"fmt"
	"reflect"
	"slices"
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

// prettyCore renders With fields with the pretty encoder, so it still sees
// each field's type: the core zap builds adds them to the encoder as an
// ObjectEncoder, which turns an error into plain strings before it can be
// rendered as a block.
type prettyCore struct {
	zapcore.Core
	enc *prettyEncoder
	out zapcore.WriteSyncer
	lvl zapcore.LevelEnabler
}

func newPrettyCore(enc *prettyEncoder, out zapcore.WriteSyncer, lvl zapcore.LevelEnabler) *prettyCore {
	return &prettyCore{Core: zapcore.NewCore(enc, out, lvl), enc: enc, out: out, lvl: lvl}
}

func (c *prettyCore) With(fields []zapcore.Field) zapcore.Core {
	return newPrettyCore(c.enc.with(fields), c.out, c.lvl)
}

// prettyEncoder writes the header (time, level, logger name, caller,
// message) as zap's console encoder would, and renders every field itself.
type prettyEncoder struct {
	// ObjectEncoder is nil: With fields reach the encoder through with, never
	// through its Add methods.
	zapcore.ObjectEncoder
	levels [zapcore.FatalLevel - zapcore.DebugLevel + 1]string
	level  zapcore.LevelEncoder

	// The With fields, as zap's encoders keep theirs: those on the header
	// line already rendered, the blocks under it still as fields (keyed with
	// their namespace), and the namespace they leave open.
	inline    []byte
	blocks    []zapcore.Field
	namespace string
}

var prettyBufs = buffer.NewPool()

func newPrettyEncoder(color bool) *prettyEncoder {
	e := &prettyEncoder{level: zapcore.CapitalLevelEncoder}
	if color {
		e.level = zapcore.CapitalColorLevelEncoder
	}
	for i := range e.levels {
		e.levels[i] = levelText(zapcore.DebugLevel+zapcore.Level(i), e.level)
	}
	return e
}

// levelText is what enc writes for l, as zap's console encoder prints it.
func levelText(l zapcore.Level, enc zapcore.LevelEncoder) string {
	m := zapcore.NewMapObjectEncoder()
	_ = m.AddArray("", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		enc(l, arr)
		return nil
	}))
	return fmt.Sprint(m.Fields[""].([]any)...)
}

func (e *prettyEncoder) Clone() zapcore.Encoder {
	clone := *e
	return &clone
}

// with returns a clone of e that adds fields to its With fields. Its slices
// are its own or shared read-only, so clones are safe to use concurrently.
func (e *prettyEncoder) with(fields []zapcore.Field) *prettyEncoder {
	clone := *e
	buf := prettyBufs.Get()
	defer buf.Free()
	buf.AppendBytes(e.inline)
	clone.namespace, clone.blocks = appendFields(buf, e.namespace, slices.Clip(e.blocks), fields)
	clone.inline = slices.Clone(buf.Bytes())
	return &clone
}

func (e *prettyEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	buf := prettyBufs.Get()
	e.appendHeader(buf, ent)
	buf.AppendBytes(e.inline)
	_, blocks := appendFields(buf, e.namespace, slices.Clip(e.blocks), fields)
	buf.AppendString(zapcore.DefaultLineEnding)

	for _, f := range blocks {
		appendBlock(buf, f)
	}
	if ent.Stack != "" {
		buf.AppendString(blockIndent)
		buf.AppendString("stacktrace:")
		appendText(buf, ent.Stack)
		buf.AppendString(zapcore.DefaultLineEnding)
	}
	return buf, nil
}

// appendHeader writes what zap's console encoder would, with a space between
// elements: the time as 15:04:05.000, the level, the logger name in
// brackets, the short caller and the message.
func (e *prettyEncoder) appendHeader(buf *buffer.Buffer, ent zapcore.Entry) {
	if !ent.Time.IsZero() {
		var clock [len("15:04:05.000")]byte
		buf.AppendBytes(appendClock(clock[:0], ent.Time))
		buf.AppendByte(' ')
	}
	if i := int(ent.Level - zapcore.DebugLevel); i >= 0 && i < len(e.levels) {
		buf.AppendString(e.levels[i])
	} else {
		buf.AppendString(levelText(ent.Level, e.level))
	}
	if ent.LoggerName != "" {
		buf.AppendString(" [")
		appendEscaped(buf, ent.LoggerName, false)
		buf.AppendByte(']')
	}
	if ent.Caller.Defined {
		buf.AppendByte(' ')
		appendCaller(buf, ent.Caller)
	}
	buf.AppendByte(' ')
	appendEscaped(buf, ent.Message, false)
}

// appendCaller writes c as zapcore.ShortCallerEncoder does: the file's last
// directory and name, and the line.
func appendCaller(buf *buffer.Buffer, c zapcore.EntryCaller) {
	file := c.File
	if i := strings.LastIndexByte(file, '/'); i >= 0 {
		if i = strings.LastIndexByte(file[:i], '/'); i >= 0 {
			file = file[i+1:]
		}
	}
	buf.AppendString(file)
	buf.AppendByte(':')
	buf.AppendInt(int64(c.Line))
}

// appendFields writes the fields that go on the header line to buf, and
// returns the namespace they leave open and blocks with those rendered under
// it appended, keyed with their namespace.
func appendFields(buf *buffer.Buffer, namespace string, blocks, fields []zapcore.Field) (string, []zapcore.Field) {
	for _, f := range fields {
		switch {
		case f.Type == zapcore.NamespaceType:
			namespace += f.Key + "."
		case f.Type == zapcore.ErrorType,
			f.Type == zapcore.StringType && strings.Contains(f.String, "\n"),
			isErrorList(f):
			f.Key = namespace + f.Key
			blocks = append(blocks, f)
		default:
			appendInline(buf, namespace, f)
		}
	}
	return namespace, blocks
}

// appendBlock writes f as an indented block: an error's chain, each error of
// a zap.Errors under its index, or a multi-line string's lines.
func appendBlock(buf *buffer.Buffer, f zapcore.Field) {
	buf.AppendString(blockIndent)
	appendEscaped(buf, f.Key, false)
	buf.AppendByte(':')
	w := &errorWriter{buf: buf, base: blockIndent, budget: maxErrorNodes}
	switch {
	case f.Type == zapcore.ErrorType:
		if err, ok := f.Interface.(error); ok {
			w.write(err, 0)
		}
	case isErrorList(f):
		w.base = blockIndent + blockIndent
		for i, err := range errorList(f) {
			if err != nil {
				buf.AppendString(zapcore.DefaultLineEnding)
				buf.AppendString(w.base)
				buf.AppendByte('[')
				buf.AppendInt(int64(i))
				buf.AppendByte(']')
				w.write(err, 0)
			}
		}
	default:
		appendText(buf, f.String)
	}
	buf.AppendString(zapcore.DefaultLineEnding)
}

// isErrorList reports whether f is a zap.Errors field. zap.Errors is an
// array of an unexported []error type, so it is found by shape.
func isErrorList(f zapcore.Field) bool {
	if f.Type != zapcore.ArrayMarshalerType {
		return false
	}
	t := reflect.TypeOf(f.Interface)
	return t != nil && t.Kind() == reflect.Slice && t.Elem() == errorType
}

// errorList returns the errors of a zap.Errors field.
func errorList(f zapcore.Field) []error {
	v := reflect.ValueOf(f.Interface)
	errs := make([]error, v.Len())
	for i := range errs {
		errs[i], _ = v.Index(i).Interface().(error)
	}
	return errs
}

// appendText writes s on the lines below the current one, each indented, so a
// stack trace keeps its real line breaks.
func appendText(buf *buffer.Buffer, s string) {
	for line := range strings.SplitSeq(strings.TrimRight(s, "\n"), "\n") {
		buf.AppendString(zapcore.DefaultLineEnding)
		buf.AppendString(blockIndent + blockIndent)
		appendEscaped(buf, line, false)
	}
}

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
