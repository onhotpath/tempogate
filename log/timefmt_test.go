package log

import (
	"math"
	"math/rand/v2"
	"testing"
	"time"
	_ "time/tzdata" // the LMT zones below, whatever the host has installed

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zapcore"
)

// zapISO8601 is what zapcore.ISO8601TimeEncoder writes for t.
func zapISO8601(t time.Time) string {
	return encodedTime(t, zapcore.ISO8601TimeEncoder)
}

func encodedTime(t time.Time, encode zapcore.TimeEncoder) string {
	enc := zapcore.NewMapObjectEncoder()
	_ = enc.AddArray("t", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		encode(t, arr)
		return nil
	}))
	return enc.Fields["t"].([]any)[0].(string)
}

func timeZones(t testing.TB) []*time.Location {
	t.Helper()
	zones := []*time.Location{
		time.UTC,
		time.Local,
		time.FixedZone("", 0),
		time.FixedZone("IST", 5*3600+30*60),
		time.FixedZone("NPT", 5*3600+45*60),
		time.FixedZone("CHAST", 12*3600+45*60),
		time.FixedZone("NST", -(3*3600 + 30*60)),
		time.FixedZone("LINT", 14*3600),
		time.FixedZone("", -12*3600),
		time.FixedZone("", 30),
		time.FixedZone("", -30),
		time.FixedZone("", -59),
		time.FixedZone("", -61),
		time.FixedZone("", 100*3600+7),
		time.FixedZone("", -(100*3600 + 7)),
	}
	// Local mean time before standard zones: offsets with seconds, both
	// signs.
	for _, name := range []string{"America/New_York", "Africa/Monrovia", "Europe/Amsterdam", "Asia/Kolkata", "Pacific/Chatham"} {
		loc, err := time.LoadLocation(name)
		require.NoError(t, err)
		zones = append(zones, loc)
	}
	return zones
}

func TestEncodeTime_MatchesISO8601TimeEncoder(t *testing.T) {
	times := []time.Time{
		fixedClock{}.Now(),
		time.Unix(0, 0),
		time.Date(1999, 12, 31, 23, 59, 59, 999999999, time.UTC),
		time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2024, 2, 29, 12, 0, 0, 1e6-1, time.UTC),
		time.Date(1800, 6, 1, 0, 0, 0, 5e6, time.UTC),
		time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(999, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(7, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(0, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(-1, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(-12345, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(9999, 12, 31, 23, 59, 59, 999e6, time.UTC),
		time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(292277026596, 12, 4, 15, 30, 7, 0, time.UTC),
		time.Unix(math.MaxInt64, 999999999),
		time.Unix(math.MinInt64, 0),
		{},
	}
	rng := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		// Mostly around now, some anywhere a time.Time can hold.
		sec := rng.Int64N(1<<34) - 1<<33
		if rng.IntN(10) == 0 {
			sec = int64(rng.Uint64())
		}
		times = append(times, time.Unix(sec, rng.Int64N(1e9)))
	}

	for _, loc := range timeZones(t) {
		for _, tm := range times {
			tm = tm.In(loc)
			want := zapISO8601(tm)
			require.Equal(t, want, encodedTime(tm, encodeTime), "%s in %s", tm, loc)
			require.Equal(t, tm.Format(iso8601Layout), want)
		}
	}
}

func FuzzEncodeTime(f *testing.F) {
	f.Add(int64(1767366245), int64(6e6), 0)
	f.Add(int64(-5364662400), int64(0), -17762)
	f.Add(int64(0), int64(999999999), -30)
	f.Add(int64(math.MaxInt64), int64(0), 3600)
	f.Fuzz(func(t *testing.T, sec, nsec int64, offset int) {
		tm := time.Unix(sec, nsec).In(time.FixedZone("", offset))
		assert.Equal(t, zapISO8601(tm), encodedTime(tm, encodeTime))
	})
}

// The pretty header's clock reads as time.Format's "15:04:05.000".
func TestAppendClock(t *testing.T) {
	for _, loc := range timeZones(t) {
		for _, tm := range []time.Time{
			fixedClock{}.Now(),
			time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC),
			time.Date(2026, 1, 2, 23, 59, 59, 999999999, time.UTC),
			time.Date(-1, 1, 2, 9, 8, 7, 1e6, time.UTC),
		} {
			tm = tm.In(loc)
			assert.Equal(t, tm.Format("15:04:05.000"), string(appendClock(nil, tm)))
		}
	}
}
