package log

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNew_BothAPIsEmit(t *testing.T) {
	for _, format := range []Format{FormatJSON, FormatPretty} {
		t.Run(string(format), func(t *testing.T) {
			var buf bytes.Buffer

			r, err := New(Params{Level: Level("info"), Format: format, Sink: &buf})
			require.NoError(t, err)

			r.Zap.Info("from-zap", zap.String("k1", "v1"))
			r.Slog.Info("from-slog", "k2", "v2")

			out := buf.String()
			assert.Contains(t, out, "from-zap")
			assert.Contains(t, out, "from-slog")
			assert.Contains(t, out, "v1")
			assert.Contains(t, out, "v2")
		})
	}
}

func TestNew_RespectsLevel(t *testing.T) {
	var buf bytes.Buffer

	r, err := New(Params{Level: Level("warn"), Sink: &buf})
	require.NoError(t, err)

	r.Zap.Info("info-suppressed")
	r.Slog.Info("info-suppressed-slog")
	r.Zap.Warn("warn-emitted")

	out := buf.String()
	assert.NotContains(t, out, "info-suppressed")
	assert.NotContains(t, out, "info-suppressed-slog")
	assert.Contains(t, out, "warn-emitted")
}

func TestNew_RejectsBadLevel(t *testing.T) {
	_, err := New(Params{Level: Level("not-a-level")})
	assert.Error(t, err)
}

func TestNew_RejectsBadFormat(t *testing.T) {
	_, err := New(Params{Level: Level("info"), Format: Format("console")})
	assert.EqualError(t, err, `LOG_FORMAT must be "auto", "json" or "pretty", got "console"`)
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"auto", "json", "pretty"} {
		f, err := ParseFormat(s)
		require.NoError(t, err)
		assert.Equal(t, Format(s), f)
	}
	for _, s := range []string{"", "console", "JSON", " json"} {
		_, err := ParseFormat(s)
		assert.Error(t, err, s)
	}
}

func TestNew_JSONShape(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(Params{Level: Level("info"), Format: FormatJSON, Sink: &buf})
	require.NoError(t, err)

	r.Zap.Named("http").Info("from-zap", zap.String("k", "v"), zap.Duration("d", time.Second))
	r.Slog.Warn("from-slog", "n", 1)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)
	var zapLine, slogLine map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &zapLine))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &slogLine))

	ts, ok := zapLine["time"].(string)
	require.True(t, ok)
	_, err = time.Parse("2006-01-02T15:04:05.000Z0700", ts)
	require.NoError(t, err, "time is ISO8601")
	delete(zapLine, "time")
	assert.Equal(t, map[string]any{"level": "info", "logger": "http", "msg": "from-zap", "k": "v", "d": "1s"}, zapLine)

	assert.Equal(t, "warn", slogLine["level"])
	assert.Equal(t, "from-slog", slogLine["msg"])
	assert.Equal(t, float64(1), slogLine["n"])
	assert.Contains(t, slogLine["caller"], "log/log_test.go:")
}

// TestNew_AutoIsJSONOffATerminal: an injected writer and a regular file are
// both not terminals, so auto picks json.
func TestNew_AutoIsJSONOffATerminal(t *testing.T) {
	var buf bytes.Buffer
	r, err := New(Params{Level: Level("info"), Sink: &buf})
	require.NoError(t, err)
	r.Zap.Info("hello")
	assert.True(t, json.Valid(buf.Bytes()), buf.String())

	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = f.Close() })
	r, err = New(Params{Level: Level("info"), Format: FormatAuto, Sink: f})
	require.NoError(t, err)
	r.Zap.Info("hello")
	b, err := os.ReadFile(f.Name())
	require.NoError(t, err)
	assert.True(t, json.Valid(b), string(b))
}

func TestResolve(t *testing.T) {
	assert.Equal(t, FormatPretty, resolve(FormatAuto, true))
	assert.Equal(t, FormatJSON, resolve(FormatAuto, false))
	assert.Equal(t, FormatJSON, resolve(FormatJSON, true))
	assert.Equal(t, FormatPretty, resolve(FormatPretty, false))
}
