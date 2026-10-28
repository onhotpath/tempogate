package log

import (
	"errors"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

type stringer string

func (s stringer) String() string { return string(s) }

type panicStringer struct{}

func (panicStringer) String() string { panic("boom") }

// inlineFields holds a field of every type appendInline writes from its
// type, and arrays it writes directly or hands to the map encoder, with the
// values most likely to tell two renderings apart.
func inlineFields() []zapcore.Field {
	ist := time.FixedZone("IST", 5*3600+30*60)
	fields := []zapcore.Field{
		zap.Skip(),
		zap.String("s", "plain"),
		zap.String("s", ""),
		zap.String("s", `a b=c "d"`),
		zap.String("s", "ctl\x1b[2J\x7f\u009b\x9b"),
		zap.ByteString("b", []byte("bytes")),
		zap.ByteString("b", []byte("\xff\x00 x")),
		zap.Bool("t", true),
		zap.Bool("f", false),
		zap.Int64("i64", math.MinInt64),
		zap.Int64("i64", math.MaxInt64),
		zap.Int32("i32", math.MinInt32),
		zap.Int16("i16", math.MinInt16),
		zap.Int8("i8", -1),
		zap.Uint64("u64", math.MaxUint64),
		zap.Uint32("u32", math.MaxUint32),
		zap.Uint16("u16", math.MaxUint16),
		zap.Uint8("u8", math.MaxUint8),
		zap.Uintptr("uptr", math.MaxUint64),
		// Wider than the type: zap narrows it.
		{Key: "i8", Type: zapcore.Int8Type, Integer: 0x1ff},
		{Key: "u8", Type: zapcore.Uint8Type, Integer: -1},
		zap.Duration("d", 0),
		zap.Duration("d", -1500*time.Millisecond),
		zap.Duration("d", math.MinInt64),
		zap.Time("at", time.Date(2026, 1, 2, 3, 4, 5, 6, ist)),
		zap.Time("at", time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		{Key: "at", Type: zapcore.TimeType, Integer: 1e18},
		zap.Time("at", time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)),
		zap.Time("at", time.Date(-1, 1, 1, 0, 0, 0, 0, ist)),
		zap.Stringer("st", stringer("x y")),
		zap.Stringer("st", panicStringer{}),
		zap.Stringer("st", (*time.Location)(nil)),
		zap.Stringer("st", (*net)(nil)),
		zap.Stringer("st", nil),
		zap.Stringer("k\x1b", stringer("v")),
		zap.Strings("a", []string{"openid", "profile"}),
		zap.Strings("a", []string{}),
		zap.Strings("a", nil),
		zap.Strings("a", []string{"", " sp=ace "}),
		zap.Strings("a", []string{"a&b", "<x>"}),
		zap.Strings("a", []string{`q"`, `b\`}),
		zap.Strings("a", []string{"ü", "\u2028", "\x7f\u009b", "\x1b\n", "\xff"}),
		zap.Ints("a", []int{-1, 0, math.MaxInt}),
		zap.Int64s("a", []int64{math.MinInt64}),
		zap.Int32s("a", []int32{-2}),
		zap.Int16s("a", []int16{-3}),
		zap.Int8s("a", []int8{-4}),
		zap.Uints("a", []uint{1}),
		zap.Uint64s("a", []uint64{math.MaxUint64}),
		zap.Uint32s("a", []uint32{2}),
		zap.Uint16s("a", []uint16{3}),
		zap.Uint8s("a", []uint8{4}),
		zap.Uintptrs("a", []uintptr{5}),
		zap.Bools("a", []bool{true, false}),
		zap.Float64s("a", []float64{1e21, 0.5}),
		zap.Float32s("a", []float32{0.1}),
		zap.Complex128s("a", []complex128{1i}),
		zap.Complex64s("a", []complex64{1i}),
		zap.Durations("a", []time.Duration{time.Second}),
		zap.Times("a", []time.Time{time.Date(2026, 1, 2, 3, 4, 5, 0, ist)}),
		zap.ByteStrings("a", [][]byte{[]byte("b")}),
		zap.Array("a", zapcore.ArrayMarshalerFunc(func(enc zapcore.ArrayEncoder) error {
			enc.AppendString("x")
			_ = enc.AppendArray(zapcore.ArrayMarshalerFunc(func(enc zapcore.ArrayEncoder) error {
				enc.AppendInt(1)
				return nil
			}))
			_ = enc.AppendObject(zapcore.ObjectMarshalerFunc(func(enc zapcore.ObjectEncoder) error {
				enc.AddString("k", "v")
				return nil
			}))
			return enc.AppendReflected(struct{ A int }{1})
		})),
		zap.Array("a", zapcore.ArrayMarshalerFunc(func(enc zapcore.ArrayEncoder) error {
			enc.AppendString("x")
			return errors.New("half done")
		})),
	}
	for _, f := range []float64{
		0, math.Copysign(0, -1), 1, -1.5, 1e6, 1e20, 1e21, 1e-4, 1e-5, 123456789.125,
		math.MaxFloat64, math.SmallestNonzeroFloat64, math.NaN(), math.Inf(1), math.Inf(-1),
	} {
		fields = append(fields, zap.Float64("f64", f), zap.Float32("f32", float32(f)))
	}
	return fields
}

// net's String has a value receiver, so a nil *net panics in it.
type net struct{ name string }

func (n net) String() string { return n.name }

// Each field renders as it does through zap's map encoder.
func TestAppendInline_MatchesMapEncoder(t *testing.T) {
	for _, ns := range []string{"", "ns.", "a\x1b.b."} {
		for _, f := range inlineFields() {
			got, want := buffer.NewPool().Get(), buffer.NewPool().Get()
			appendInline(got, ns, f)
			appendMapped(want, ns, f)
			assert.Equal(t, want.String(), got.String(), "%s %#v", ns, f)
		}
	}
}

func TestAppendInline_Values(t *testing.T) {
	z, buf := prettyLogger(false)
	z.Info("m",
		zap.Uint64("max", math.MaxUint64),
		zap.Float64("nan", math.NaN()),
		zap.Float64("inf", math.Inf(1)),
		zap.Float64("ninf", math.Inf(-1)),
		zap.Float32("f32", 0.1),
		zap.Duration("neg", -90*time.Second),
		zap.Stringer("panics", panicStringer{}),
		zap.Stringer("nilptr", (*net)(nil)),
		zap.Skip(),
	)
	assert.Equal(t, "15:04:05.006 INFO m max=18446744073709551615 nan=NaN inf=+Inf ninf=-Inf f32=0.1 "+
		`neg=-1m30s panicsError="PANIC=boom" nilptr=<nil>`+"\n", buf.String())
}

// Numbers held in a map encoder print as fmt's %v.
func TestAppendValue_NumbersMatchFmt(t *testing.T) {
	values := []any{
		int(-1), int64(math.MinInt64), int32(-2), int16(-3), int8(-4),
		uint(1), uint64(math.MaxUint64), uint32(2), uint16(3), uint8(4), uintptr(5),
	}
	for _, f := range []float64{0, math.Copysign(0, -1), 1e21, 1e20, 1e-5, 0.1, math.NaN(), math.Inf(1), math.Inf(-1), math.MaxFloat64} {
		values = append(values, f, float32(f))
	}
	for _, v := range values {
		buf := buffer.NewPool().Get()
		appendValue(buf, v)
		assert.Equal(t, fmt.Sprint(v), buf.String(), "%T", v)
	}
}

// A value encoding/json cannot marshal is written as its %v.
func TestAppendValue_UnmarshalableFallsBackToText(t *testing.T) {
	buf := buffer.NewPool().Get()
	appendValue(buf, map[string]any{"f": math.Inf(1)})
	assert.Equal(t, `map[f:+Inf]`, buf.String())
}

func TestEscapeControls(t *testing.T) {
	for in, want := range map[string]string{
		"":                 "",
		"plain ü":          "plain ü",
		"a\nb\rc\td":       `a\nb\rc` + "\td",
		"\x1b[2J\x7f":      `\x1b[2J\x7f`,
		"c1 \u009b end":    `c1 \x9b end`,
		"bad \xff\xfe":     `bad \xff\xfe`,
		"cut \xe2\x82":     `cut \xe2\x82`,
		"keep �":           "keep �",
		"\x00\x01\x1f end": `\x00\x01\x1f end`,
	} {
		assert.Equal(t, want, escapeControls(in, false), "%q", in)
	}
	assert.Equal(t, "a\nb\\r", escapeControls("a\nb\r", true))
	assert.Equal(t, `x`, escapeControls("x", true))
}
