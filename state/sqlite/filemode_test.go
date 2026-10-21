//go:build unix

package sqlite

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

// withUmask runs the test under the permissive umask most hosts and
// containers default to, so a file the store does not restrict explicitly
// comes out world-readable.
func withUmask(t *testing.T, mask int) {
	t.Helper()
	old := syscall.Umask(mask)
	t.Cleanup(func() { syscall.Umask(old) })
}

func requireMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equalf(t, want, info.Mode().Perm(), "%s is %s", path, info.Mode().Perm())
}

// writeSomething makes SQLite create the -wal and -shm files.
func writeSomething(t *testing.T, s *Store) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, s.Migrate(ctx))
	now := time.Now().UTC()
	require.NoError(t, s.SaveBrowserSession(ctx, browserSessionAt("sid-mode", now)))
}

func TestNewCreatesOwnerOnlyDirAndFiles(t *testing.T) {
	withUmask(t, 0o022)
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "state.db")

	s, err := New(WithPath(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	writeSomething(t, s)

	requireMode(t, dir, 0o700)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		requireMode(t, path+suffix, 0o600)
	}
}

func TestNewTightensExistingFiles(t *testing.T) {
	withUmask(t, 0o022)
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")

	// A database left by an earlier version, with the modes it created.
	s, err := New(WithPath(path))
	require.NoError(t, err)
	writeSomething(t, s)
	for _, suffix := range []string{"", "-wal", "-shm"} {
		require.NoError(t, os.Chmod(path+suffix, 0o644))
	}

	reopened, err := New(WithPath(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	for _, suffix := range []string{"", "-wal", "-shm"} {
		requireMode(t, path+suffix, 0o600)
	}
	require.NoError(t, s.Close())
}

// A pre-existing directory may be shared (a mounted volume, /tmp) and its
// mode is the operator's: the store leaves it alone and only warns when it
// lets other users in.
func TestNewLeavesExistingDirAndWarnsWhenWorldAccessible(t *testing.T) {
	withUmask(t, 0o022)
	dir := filepath.Join(t.TempDir(), "shared")
	require.NoError(t, os.Mkdir(dir, 0o755))
	require.NoError(t, os.Chmod(dir, 0o755))

	core, logs := observer.New(zap.WarnLevel)
	s, err := New(WithPath(filepath.Join(dir, "state.db")), WithLogger(zap.New(core)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	writeSomething(t, s)

	requireMode(t, dir, 0o755)
	requireMode(t, filepath.Join(dir, "state.db"), 0o600)
	require.Equal(t, 1, logs.FilterMessageSnippet("accessible to other users").Len(), "warns once")
}

// A group-accessible directory is what a Kubernetes fsGroup volume looks
// like; that is intended and does not warn.
func TestNewDoesNotWarnForGroupAccessibleDir(t *testing.T) {
	withUmask(t, 0o022)
	dir := filepath.Join(t.TempDir(), "pvc")
	require.NoError(t, os.Mkdir(dir, 0o770))
	require.NoError(t, os.Chmod(dir, 0o2770))

	core, logs := observer.New(zap.WarnLevel)
	s, err := New(WithPath(filepath.Join(dir, "state.db")), WithLogger(zap.New(core)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	writeSomething(t, s)

	require.Zero(t, logs.Len())
	requireMode(t, filepath.Join(dir, "state.db"), 0o600)
}

// The raw secrets must not reach any file SQLite writes, including the WAL
// (where deleted rows linger until a checkpoint).
func TestDatabaseFilesNeverContainRawSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.db")
	s, err := New(WithPath(path))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	secrets := seedEverySecret(t, s)

	scan := func(when string) {
		for _, suffix := range []string{"", "-wal", "-shm"} {
			b, err := os.ReadFile(path + suffix)
			if os.IsNotExist(err) {
				continue
			}
			require.NoError(t, err)
			for name, v := range secrets {
				require.Falsef(t, bytes.Contains(b, []byte(v)), "%s: raw %s found in state.db%s", when, name, suffix)
			}
		}
	}
	scan("while open")
	require.NoError(t, s.Close())
	scan("after close")
}

func TestNewFailsWhenStateDirIsUnreachable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	locked := filepath.Join(t.TempDir(), "locked")
	require.NoError(t, os.Mkdir(locked, 0o700))
	require.NoError(t, os.Chmod(locked, 0))
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	_, err := New(WithPath(filepath.Join(locked, "state", "state.db")))
	require.ErrorContains(t, err, "stat state directory")
}

func TestNewFailsWhenStateDirCannotBeCreated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	parent := filepath.Join(t.TempDir(), "ro")
	require.NoError(t, os.Mkdir(parent, 0o500))
	_, err := New(WithPath(filepath.Join(parent, "state", "state.db")))
	require.ErrorContains(t, err, "create state directory")
}
