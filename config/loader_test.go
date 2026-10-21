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
	src, err := Load(c, path)
	require.NoError(t, err)
	require.Equal(t, Source{Path: path}, src)
	require.Equal(t, "debug", c.Log.Level)
	require.Equal(t, "0.0.0.0:8000", c.HTTP.Listener.String())
	require.Equal(t, "/tmp/from-yaml.db", c.State.Sqlite.Path)
	require.Equal(t, 3*time.Second, c.State.Sqlite.BusyTimeout)
	require.Equal(t, "from-env", c.OIDC.Google.ClientID)
	require.Equal(t, "https://accounts.google.com", c.OIDC.Google.IssuerURL)
}

func TestLoadUsesApplicationYAMLInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "application.yaml"), []byte("log:\n  level: trace\n"), 0o600))
	t.Chdir(dir)
	c := defaultConfig()
	src, err := Load(c, "")
	require.NoError(t, err)
	require.Equal(t, Source{Path: "application.yaml"}, src)
	require.Equal(t, "trace", c.Log.Level)
}

// A file in a parent directory is not the operator's: on a shared host anyone
// who can write to /tmp or a home directory above the cwd could otherwise
// point the Google endpoints at their own IdP.
func TestLoadIgnoresApplicationYAMLInParentDirectories(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "application.yaml"),
		[]byte("oidc:\n  google:\n    auth_endpoint: https://attacker.example/auth\n"), 0o600))
	deep := filepath.Join(root, "one", "two", "three")
	require.NoError(t, os.MkdirAll(deep, 0o700))
	for _, dir := range []string{filepath.Join(root, "one"), deep} {
		t.Run(dir, func(t *testing.T) {
			t.Chdir(dir)
			c := defaultConfig()
			src, err := Load(c, "")
			require.NoError(t, err)
			require.Equal(t, Source{}, src)
			require.Equal(t, "https://accounts.google.com/o/oauth2/v2/auth", c.OIDC.Google.AuthEndpoint)
		})
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission checks do not apply to root")
	}
}

// The container runs in /home/nonroot; under any uid other than the image
// default that directory is unreadable, and the implicit lookup must not turn
// that into a startup failure.
func TestLoadSkipsUnreadableWorkingDirectory(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "application.yaml"), []byte("log:\n  level: trace\n"), 0o600))
	t.Chdir(dir)
	require.NoError(t, os.Chmod(dir, 0))
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	t.Setenv("LOG_LEVEL", "warn")

	c := defaultConfig()
	src, err := Load(c, "")
	require.NoError(t, err)
	require.Empty(t, src.Path)
	require.ErrorIs(t, src.Skipped, os.ErrPermission)
	require.Equal(t, "warn", c.Log.Level, "environment is still applied")
}

func TestLoadSkipsUnreadableImplicitFile(t *testing.T) {
	skipIfRoot(t)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "application.yaml"), []byte("log:\n  level: trace\n"), 0))
	t.Chdir(dir)

	c := defaultConfig()
	src, err := Load(c, "")
	require.NoError(t, err)
	require.Empty(t, src.Path)
	require.ErrorIs(t, src.Skipped, os.ErrPermission)
	require.Equal(t, "info", c.Log.Level)
}

// An operator who names a file means it: failing to read it is fatal.
func TestLoadRejectsUnreadableExplicitFile(t *testing.T) {
	skipIfRoot(t)
	path := filepath.Join(t.TempDir(), "custom.yaml")
	require.NoError(t, os.WriteFile(path, []byte("log:\n  level: trace\n"), 0))
	_, err := Load(defaultConfig(), path)
	require.ErrorIs(t, err, os.ErrPermission)
	require.ErrorContains(t, err, path)
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

func TestNewFailsOnMissingExplicitFile(t *testing.T) {
	_, err := New(Params{Path: Path(filepath.Join(t.TempDir(), "missing.yaml"))})
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestLoadServerHardeningFromYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "application.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`server:
  read_timeout: 7s
  max_header_bytes: 4096
`), 0o600))
	t.Setenv("SERVER_SHUTDOWN_TIMEOUT", "3s")

	c := defaultConfig()
	_, err := Load(c, path)
	require.NoError(t, err)
	require.Equal(t, 7*time.Second, c.Server.ReadTimeout)
	require.Equal(t, 4096, c.Server.MaxHeaderBytes)
	require.Equal(t, 3*time.Second, c.Server.ShutdownTimeout)
	require.Equal(t, 30*time.Second, c.Server.WriteTimeout, "unset keys keep their defaults")
}
