package log

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

// appendInline writes f as " key=value". A scalar, or an array of plain
// scalars, is written from its type, as zap's map encoder would hold it;
// anything else goes through that encoder, since it can expand to several
// keys (zap.Inline) or nest.
func appendInline(buf *buffer.Buffer, namespace string, f zapcore.Field) {
	switch f.Type {
	case zapcore.SkipType:
		// Nothing, as zap writes nothing.
	case zapcore.StringType:
		appendKey(buf, namespace, f.Key)
		appendString(buf, f.String)
	case zapcore.ByteStringType:
		appendKey(buf, namespace, f.Key)
		appendString(buf, string(f.Interface.([]byte)))
	case zapcore.BoolType:
		appendKey(buf, namespace, f.Key)
		buf.AppendBool(f.Integer == 1)
	case zapcore.Int64Type, zapcore.Int32Type, zapcore.Int16Type, zapcore.Int8Type:
		appendKey(buf, namespace, f.Key)
		buf.AppendInt(signed(f))
	case zapcore.Uint64Type, zapcore.Uint32Type, zapcore.Uint16Type, zapcore.Uint8Type, zapcore.UintptrType:
		appendKey(buf, namespace, f.Key)
		buf.AppendUint(unsigned(f))
	case zapcore.Float64Type, zapcore.Float32Type:
		v, bitSize := fieldFloat(f)
		appendKey(buf, namespace, f.Key)
		appendFloat(buf, v, bitSize)
	case zapcore.DurationType:
		appendKey(buf, namespace, f.Key)
		buf.AppendString(time.Duration(f.Integer).String())
	case zapcore.TimeType:
		t := time.Unix(0, f.Integer)
		if f.Interface != nil {
			t = t.In(f.Interface.(*time.Location))
		}
		appendKey(buf, namespace, f.Key)
		buf.AppendTime(t, time.RFC3339Nano)
	case zapcore.TimeFullType:
		appendKey(buf, namespace, f.Key)
		buf.AppendTime(f.Interface.(time.Time), time.RFC3339Nano)
	case zapcore.StringerType:
		// As zap does, a panic is reported under "<key>Error".
		s, panicked := recoverText(f.Interface, func() string { return f.Interface.(fmt.Stringer).String() })
		if panicked {
			appendKey(buf, namespace, f.Key+"Error")
		} else {
			appendKey(buf, namespace, f.Key)
		}
		appendString(buf, s)
	case zapcore.ArrayMarshalerType:
		if !appendPlainArray(buf, namespace, f) {
			appendMapped(buf, namespace, f)
		}
	default:
		appendMapped(buf, namespace, f)
	}
}

// signed is the value of an integer field, at the width zap gives it.
//
//nolint:gosec // G115: narrowed as zap narrows it
func signed(f zapcore.Field) int64 {
	switch f.Type {
	case zapcore.Int32Type:
		return int64(int32(f.Integer))
	case zapcore.Int16Type:
		return int64(int16(f.Integer))
	case zapcore.Int8Type:
		return int64(int8(f.Integer))
	default:
		return f.Integer
	}
}

// unsigned is the value of an unsigned integer field, at the width zap
// gives it.
//
//nolint:gosec // G115: narrowed as zap narrows it
func unsigned(f zapcore.Field) uint64 {
	switch f.Type {
	case zapcore.Uint32Type:
		return uint64(uint32(f.Integer))
	case zapcore.Uint16Type:
		return uint64(uint16(f.Integer))
	case zapcore.Uint8Type:
		return uint64(uint8(f.Integer))
	case zapcore.UintptrType:
		return uint64(uintptr(f.Integer))
	default:
		return uint64(f.Integer)
	}
}

// fieldFloat is the value and bit size of a float field.
//
//nolint:gosec // G115: the bits zap stored
func fieldFloat(f zapcore.Field) (float64, int) {
	if f.Type == zapcore.Float32Type {
		return float64(math.Float32frombits(uint32(f.Integer))), 32
	}
	return math.Float64frombits(uint64(f.Integer)), 64
}

// appendMapped writes f through a map encoder, each key it adds as its own
// pair, sorted.
func appendMapped(buf *buffer.Buffer, namespace string, f zapcore.Field) {
	m := zapcore.NewMapObjectEncoder()
	f.AddTo(m)
	dropVerbose(m.Fields)
	keys := make([]string, 0, 4)
	for k := range m.Fields {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		appendKey(buf, namespace, k)
		appendValue(buf, m.Fields[k])
	}
}

// appendPlainArray writes an array field of strings, bools and integers
// (zap.Strings, zap.Ints and the like) as appendMapped would, without
// building it as values first. It writes nothing and reports false for any
// other array, or a string that encoding/json would escape.
func appendPlainArray(buf *buffer.Buffer, namespace string, f zapcore.Field) bool {
	a := plainArray{buf: prettyBufs.Get()}
	defer a.buf.Free()
	if err := f.Interface.(zapcore.ArrayMarshaler).MarshalLogArray(&a); err != nil || a.other {
		return false
	}
	appendKey(buf, namespace, f.Key)
	buf.AppendByte('[')
	buf.AppendBytes(a.buf.Bytes())
	buf.AppendByte(']')
	return true
}

// plainArray is the zapcore.ArrayEncoder behind appendPlainArray. It writes
// the elements encoding/json and this encoder agree on, and notes any other.
type plainArray struct {
	buf   *buffer.Buffer
	n     int
	other bool
}

func (a *plainArray) next() {
	if a.n > 0 {
		a.buf.AppendByte(',')
	}
	a.n++
}

func (a *plainArray) AppendString(s string) {
	if !isPlainJSON(s) {
		a.other = true
		return
	}
	a.next()
	a.buf.AppendByte('"')
	a.buf.AppendString(s)
	a.buf.AppendByte('"')
}

func (a *plainArray) AppendBool(v bool) {
	a.next()
	a.buf.AppendBool(v)
}

func (a *plainArray) AppendInt64(v int64) {
	a.next()
	a.buf.AppendInt(v)
}

func (a *plainArray) AppendUint64(v uint64) {
	a.next()
	a.buf.AppendUint(v)
}

func (a *plainArray) AppendInt(v int)         { a.AppendInt64(int64(v)) }
func (a *plainArray) AppendInt32(v int32)     { a.AppendInt64(int64(v)) }
func (a *plainArray) AppendInt16(v int16)     { a.AppendInt64(int64(v)) }
func (a *plainArray) AppendInt8(v int8)       { a.AppendInt64(int64(v)) }
func (a *plainArray) AppendUint(v uint)       { a.AppendUint64(uint64(v)) }
func (a *plainArray) AppendUint32(v uint32)   { a.AppendUint64(uint64(v)) }
func (a *plainArray) AppendUint16(v uint16)   { a.AppendUint64(uint64(v)) }
func (a *plainArray) AppendUint8(v uint8)     { a.AppendUint64(uint64(v)) }
func (a *plainArray) AppendUintptr(v uintptr) { a.AppendUint64(uint64(v)) }

// encoding/json writes floats, durations and times its own way.
func (a *plainArray) AppendByteString([]byte)                    { a.other = true }
func (a *plainArray) AppendFloat64(float64)                      { a.other = true }
func (a *plainArray) AppendFloat32(float32)                      { a.other = true }
func (a *plainArray) AppendComplex128(complex128)                { a.other = true }
func (a *plainArray) AppendComplex64(complex64)                  { a.other = true }
func (a *plainArray) AppendDuration(time.Duration)               { a.other = true }
func (a *plainArray) AppendTime(time.Time)                       { a.other = true }
func (a *plainArray) AppendArray(zapcore.ArrayMarshaler) error   { a.other = true; return nil }
func (a *plainArray) AppendObject(zapcore.ObjectMarshaler) error { a.other = true; return nil }
func (a *plainArray) AppendReflected(any) error                  { a.other = true; return nil }

// isPlainJSON reports whether s is printable ASCII that encoding/json writes
// as it is: no quote, backslash or HTML character.
func isPlainJSON(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c >= 0x7f || strings.IndexByte(`"\\<>&`, c) >= 0 {
			return false
		}
	}
	return true
}

func appendKey(buf *buffer.Buffer, namespace, key string) {
	buf.AppendByte(' ')
	appendEscaped(buf, namespace, false)
	appendEscaped(buf, key, false)
	buf.AppendByte('=')
}

// dropVerbose removes the "<key>Verbose" that zap adds beside an error's
// "<key>" when the error is a fmt.Formatter, from an error nested in an
// object or array: its %+v is what the pretty format leaves out.
func dropVerbose(v any) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if base, ok := strings.CutSuffix(k, "Verbose"); ok && base != "" {
				if _, ok := v[base]; ok {
					delete(v, k)
					continue
				}
			}
			dropVerbose(x)
		}
	case []any:
		for _, x := range v {
			dropVerbose(x)
		}
	}
}

// appendValue writes a value as zap's map encoder holds it.
func appendValue(buf *buffer.Buffer, v any) {
	switch v := v.(type) {
	case string:
		appendString(buf, v)
	case bool:
		buf.AppendBool(v)
	case int:
		buf.AppendInt(int64(v))
	case int64:
		buf.AppendInt(v)
	case int32:
		buf.AppendInt(int64(v))
	case int16:
		buf.AppendInt(int64(v))
	case int8:
		buf.AppendInt(int64(v))
	case uint:
		buf.AppendUint(uint64(v))
	case uint64:
		buf.AppendUint(v)
	case uint32:
		buf.AppendUint(uint64(v))
	case uint16:
		buf.AppendUint(uint64(v))
	case uint8:
		buf.AppendUint(uint64(v))
	case uintptr:
		buf.AppendUint(uint64(v))
	case float64:
		appendFloat(buf, v, 64)
	case float32:
		appendFloat(buf, float64(v), 32)
	case time.Duration:
		buf.AppendString(v.String())
	case time.Time:
		buf.AppendTime(v, time.RFC3339Nano)
	default:
		// Objects, arrays and reflected values stay inline as JSON.
		b, err := json.Marshal(v)
		if err != nil {
			appendString(buf, fmt.Sprint(v))
			return
		}
		appendJSON(buf, b)
	}
}

// appendFloat writes f as fmt's %v does: the shortest 'g' form, NaN, +Inf
// or -Inf.
func appendFloat(buf *buffer.Buffer, f float64, bitSize int) {
	var b [32]byte
	buf.AppendBytes(strconv.AppendFloat(b[:0], f, 'g', -1, bitSize))
}

// appendString quotes s only when it would not read back as one token, or
// holds anything a terminal would act on.
func appendString(buf *buffer.Buffer, s string) {
	if s == "" || !utf8.ValidString(s) || strings.IndexFunc(s, func(r rune) bool {
		return r == '=' || r == '"' || unicode.IsSpace(r) || !unicode.IsPrint(r)
	}) >= 0 {
		buf.AppendString(strconv.Quote(s))
		return
	}
	buf.AppendString(s)
}

// appendJSON writes JSON from encoding/json, escaping DEL and C1, which it
// leaves as they are.
func appendJSON(buf *buffer.Buffer, b []byte) {
	start := 0
	for i := 0; i < len(b); {
		r, n := utf8.DecodeRune(b[i:])
		if r == 0x7f || r >= 0x80 && r <= 0x9f {
			buf.AppendBytes(b[start:i])
			buf.AppendString(`\u00`)
			appendHex(buf, r)
			start = i + n
		}
		i += n
	}
	buf.AppendBytes(b[start:])
}

// recoverText returns text(), recovering from a panic as zap does: when v
// is a nil pointer the text is <nil>, otherwise PANIC=<value> and panicked
// is set.
func recoverText(v any, text func() string) (s string, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			if rv := reflect.ValueOf(v); rv.Kind() == reflect.Pointer && rv.IsNil() {
				s = "<nil>"
				return
			}
			s, panicked = fmt.Sprintf("PANIC=%v", r), true
		}
	}()
	return text(), false
}

// appendEscaped writes s with control characters made visible: C0 (but tab,
// and newline when newline is set), DEL, C1 and bytes that are not UTF-8,
// any of which a terminal may act on. A newline outside a block would start
// a line that looks like another entry.
func appendEscaped(buf *buffer.Buffer, s string, newline bool) {
	start := 0
	for i := 0; i < len(s); {
		r, n := rune(s[i]), 1
		if r >= utf8.RuneSelf {
			r, n = utf8.DecodeRuneInString(s[i:])
		}
		invalid := r == utf8.RuneError && n == 1
		if !invalid && !isControl(r, newline) {
			i += n
			continue
		}
		buf.AppendString(s[start:i])
		switch {
		case invalid:
			buf.AppendString(`\x`)
			appendHex(buf, rune(s[i]))
		case r == '\n':
			buf.AppendString(`\n`)
		case r == '\r':
			buf.AppendString(`\r`)
		default:
			buf.AppendString(`\x`)
			appendHex(buf, r)
		}
		i += n
		start = i
	}
	buf.AppendString(s[start:])
}

// escapeControls is appendEscaped for a string.
func escapeControls(s string, newline bool) string {
	if !strings.ContainsFunc(s, func(r rune) bool { return isControl(r, newline) }) && utf8.ValidString(s) {
		return s
	}
	buf := prettyBufs.Get()
	defer buf.Free()
	appendEscaped(buf, s, newline)
	return buf.String()
}

func isControl(r rune, newline bool) bool {
	switch {
	case r == '\t', r == '\n' && newline:
		return false
	case r < 0x20, r == 0x7f:
		return true
	default:
		return r >= 0x80 && r <= 0x9f
	}
}

// appendHex writes r, which must be below 0x100, as two hex digits.
func appendHex(buf *buffer.Buffer, r rune) {
	buf.AppendByte(digits[r>>4&0xf])
	buf.AppendByte(digits[r&0xf])
}
