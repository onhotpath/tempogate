package log

import (
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// openPTY returns both ends of a new pseudo-terminal.
func openPTY(t *testing.T) (master, tty *os.File) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Skipf("no pseudo-terminal: %v", err)
	}
	master = os.NewFile(uintptr(fd), "/dev/ptmx")
	t.Cleanup(func() { _ = master.Close() })
	require.NoError(t, unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0))
	n, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	require.NoError(t, err)
	tty, err = os.OpenFile("/dev/pts/"+strconv.Itoa(n), os.O_RDWR|unix.O_NOCTTY, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tty.Close() })
	return master, tty
}

// TestNew_AutoIsPrettyOnATerminal: auto picks pretty, coloured, on a real
// terminal.
func TestNew_AutoIsPrettyOnATerminal(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	master, tty := openPTY(t)

	r, err := New(Params{Level: "info", Sink: tty})
	require.NoError(t, err)
	r.Zap.Error("stop")

	buf := make([]byte, 256)
	n, err := master.Read(buf)
	require.NoError(t, err)
	out := string(buf[:n])
	assert.Contains(t, out, "\x1b[31mERROR\x1b[0m stop")
	assert.False(t, strings.HasPrefix(out, "{"), out)
}
