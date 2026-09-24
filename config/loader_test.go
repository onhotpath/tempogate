package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadLayersYAMLAndEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`log:
  level: warn
http:
  listener: 127.0.0.1:9000
state:
  sqlite:
    path: /tmp/from-yaml.db
    busy_timeout: 2s
oidc:
  google:
    client_id: from-yaml
`), 0o600))
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("HTTP_LISTENER", "0.0.0.0:8000")
	t.Setenv("STATE_SQLITE_BUSY_TIMEOUT", "3s")
	t.Setenv("OIDC_GOOGLE_CLIENT_ID", "from-env")

	c := defaultConfig()
	used, err := Load(c, path)
	require.NoError(t, err)
	require.Equal(t, path, used)
	require.Equal(t, "debug", c.Log.Level)
	require.Equal(t, "0.0.0.0:8000", c.HTTP.Listener.String())
	require.Equal(t, "/tmp/from-yaml.db", c.State.Sqlite.Path)
	require.Equal(t, 3*time.Second, c.State.Sqlite.BusyTimeout)
	require.Equal(t, "from-env", c.OIDC.Google.ClientID)
	require.Equal(t, "https://accounts.google.com", c.OIDC.Google.IssuerURL)
}

func TestLoadSearchesFourDirectories(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "application.yaml")
	require.NoError(t, os.WriteFile(path, []byte("log:\n  level: trace\n"), 0o600))
	deep := filepath.Join(root, "one", "two", "three")
	require.NoError(t, os.MkdirAll(deep, 0o700))
	t.Chdir(deep)
	c := defaultConfig()
	used, err := Load(c, "")
	require.NoError(t, err)
	require.Equal(t, path, used)
	require.Equal(t, "trace", c.Log.Level)
}

func TestLoadRejectsMissingExplicitFileAndMalformedYAML(t *testing.T) {
	c := defaultConfig()
	_, err := Load(c, filepath.Join(t.TempDir(), "missing.yaml"))
	require.ErrorIs(t, err, os.ErrNotExist)
	_, err = Load(c, t.TempDir())
	require.ErrorContains(t, err, "is a directory")
	path := filepath.Join(t.TempDir(), "broken.yaml")
	require.NoError(t, os.WriteFile(path, []byte("oidc: [\n"), 0o600))
	_, err = Load(c, path)
	require.Error(t, err)
	require.Contains(t, err.Error(), path)
}

func TestLoadEmptyEnvironmentOverridesYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "application.yaml")
	require.NoError(t, os.WriteFile(path, []byte("oidc:\n  clients: registered\n"), 0o600))
	t.Setenv("OIDC_CLIENTS", "")
	c := defaultConfig()
	_, err := Load(c, path)
	require.NoError(t, err)
	require.Empty(t, c.OIDC.Clients)
}

func TestLoadUsesSingleUnderscoreEnvironmentNames(t *testing.T) {
	t.Setenv("HTTP_LISTENER", "0.0.0.0:9999")
	c := defaultConfig()
	_, err := Load(c, "")
	require.NoError(t, err)
	require.Equal(t, "0.0.0.0:9999", c.HTTP.Listener.String())
}

func TestLoadRejectsInvalidDurationAndListener(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"OIDC_SESSION_TTL", "forever"},
		{"HTTP_LISTENER", "localhost:8000"},
		{"ADMIN_LISTENER", "127.0.0.1:70000"},
	} {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			t.Setenv(tc.key, tc.value)
			_, err := Load(defaultConfig(), "")
			require.Error(t, err)
			require.True(t, strings.Contains(err.Error(), "ferry:"), err)
		})
	}
}
