package log

import (
	"strconv"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
)

// iso8601Layout is what encodeTime writes, as zapcore.ISO8601TimeEncoder
// does.
const iso8601Layout = "2006-01-02T15:04:05.000Z0700"

// timeBufs holds the scratch encodeTime formats into. A local array would
// escape through the encoder interface and cost an allocation per entry.
var timeBufs = sync.Pool{New: func() any { return new([32]byte) }}

// encodeTime writes t exactly as zapcore.ISO8601TimeEncoder does, but
// without parsing the layout on every call, which was most of the JSON
// encoder's time per entry.
func encodeTime(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	b := timeBufs.Get().(*[32]byte)
	enc.AppendByteString(appendISO8601(b[:0], t))
	timeBufs.Put(b)
}

// appendISO8601 appends t in iso8601Layout, following time.Format to the
// byte: a year padded to at least four digits, milliseconds truncated, "Z"
// for a zero offset and otherwise ±hhmm, with the offset's seconds dropped
// toward zero (so a -30s offset is "+0000").
func appendISO8601(b []byte, t time.Time) []byte {
	year, month, day := t.Date()
	b = appendPadded(b, year, 4)
	b = append(b, '-')
	b = append2(b, int(month))
	b = append(b, '-')
	b = append2(b, day)
	b = append(b, 'T')
	b = appendClock(b, t)

	_, offset := t.Zone()
	if offset == 0 {
		return append(b, 'Z')
	}
	zone := offset / 60
	if zone < 0 {
		b = append(b, '-')
		zone = -zone
	} else {
		b = append(b, '+')
	}
	b = appendPadded(b, zone/60, 2)
	return append2(b, zone%60)
}

// appendClock appends t as "15:04:05.000".
func appendClock(b []byte, t time.Time) []byte {
	hour, minute, sec := t.Clock()
	ms := t.Nanosecond() / 1e6
	b = append2(b, hour)
	b = append(b, ':')
	b = append2(b, minute)
	b = append(b, ':')
	b = append2(b, sec)
	return append(b, '.', digits[ms/100], digits[ms/10%10], digits[ms%10])
}

const digits = "0123456789abcdef"

// append2 appends x, which must be in [0, 99], as two digits.
func append2(b []byte, x int) []byte {
	return append(b, digits[x/10], digits[x%10])
}

// appendPadded appends x in decimal, zero-padded to width digits after any
// sign, as time.Format pads its fields.
func appendPadded(b []byte, x, width int) []byte {
	if width == 4 && x >= 0 && x < 1e4 {
		return append(b, digits[x/1000], digits[x/100%10], digits[x/10%10], digits[x%10])
	}
	if width == 2 && x >= 0 && x < 100 {
		return append2(b, x)
	}
	if x < 0 {
		b = append(b, '-')
		x = -x
	}
	for i, p := 1, 10; i < width; i, p = i+1, p*10 {
		if x < p {
			b = append(b, '0')
		}
	}
	return strconv.AppendInt(b, int64(x), 10)
}
