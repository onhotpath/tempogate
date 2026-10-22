//go:build e2e

package e2e

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/onhotpath/tempogate/state/postgres"
)

// E2E_STATE_DRIVER picks the state store the tempogate stacks run on. Unset
// (or sqlite) keeps each on its SQLite state volume. postgres gives every
// stack that calls withStateBackend a PostgreSQL of its own on the test
// network instead: `make test-e2e-postgres-go` runs the CLI login, device
// login, refresh lifecycle and integration-key tests that way, one replica
// each, unchanged otherwise.
const stateDriverEnv = "E2E_STATE_DRIVER"

var statePostgresImage = imageOr("E2E_STATE_POSTGRES_IMAGE", "postgres:18-alpine@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792")

func onPostgres() bool { return os.Getenv(stateDriverEnv) == "postgres" }

// skipOnPostgres skips a test that inspects the SQLite state file itself.
func skipOnPostgres(t *testing.T) {
	t.Helper()
	if onPostgres() {
		t.Skipf("inspects the SQLite state volume; %s=postgres", stateDriverEnv)
	}
}

// stateDBs maps a network to its state database container, so a stack
// restarted on the same network keeps its state and a test can read it.
var stateDBs sync.Map

// withStateBackend points env at the state store E2E_STATE_DRIVER selects.
// For postgres it starts the network's database on first use, owned by
// owner, as alias tempogate-db; the plain-connection opt-in is needed
// because the database is a container on the private test network.
func withStateBackend(ctx context.Context, owner *testing.T, netName string, env map[string]string) {
	owner.Helper()
	if !onPostgres() {
		return
	}
	if _, started := stateDBs.Load(netName); !started {
		db, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:          statePostgresImage,
				Env:            map[string]string{"POSTGRES_USER": "tempogate", "POSTGRES_PASSWORD": "tempogate", "POSTGRES_DB": "tempogate"},
				ExposedPorts:   []string{"5432/tcp"},
				Networks:       []string{netName},
				NetworkAliases: map[string][]string{netName: {"tempogate-db"}},
				WaitingFor: wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		track(ctx, owner, "tempogate-db", db)
		require.NoError(owner, err, "state postgres")
		stateDBs.Store(netName, db)
		owner.Cleanup(func() { stateDBs.Delete(netName) })
	}
	env["STATE_DRIVER"] = "postgres"
	env["STATE_POSTGRES_DSN"] = "postgres://tempogate:tempogate@tempogate-db:5432/tempogate?sslmode=disable"
	env["STATE_POSTGRES_ALLOW_INSECURE_SSLMODE"] = "true"
}

// runMigrate runs `tempogate migrate` from req to completion and fails t,
// with the migrate logs, unless it exits 0, so a broken migrate fails here
// rather than later as a serve that cannot start. It joins netName, where a
// postgres state database answers as tempogate-db; owner keeps the container
// (and so its logs) until the stack is torn down.
func runMigrate(ctx context.Context, t, owner *testing.T, name, netName string, req testcontainers.ContainerRequest) {
	t.Helper()
	req.Cmd = []string{"migrate"}
	req.Networks = []string{netName}
	req.WaitingFor = wait.ForExit().WithExitTimeout(2 * time.Minute)
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{ContainerRequest: req, Started: true})
	track(ctx, owner, name, c)
	require.NoError(t, err, name)
	st, err := c.State(ctx)
	require.NoError(t, err, name)
	require.Equalf(t, 0, st.ExitCode, "%s exited %d:\n%s", name, st.ExitCode, containerLogs(ctx, t, c))
}

// postgresStateStore opens the state database withStateBackend started on
// netName from the host, through its mapped port, with the store tempogate
// itself uses.
func postgresStateStore(ctx context.Context, t *testing.T, netName string) *postgres.Store {
	t.Helper()
	v, ok := stateDBs.Load(netName)
	require.Truef(t, ok, "no state database on network %s", netName)
	host, err := v.(testcontainers.Container).PortEndpoint(ctx, "5432/tcp", "")
	require.NoError(t, err, "state postgres endpoint")
	store, err := postgres.New(
		postgres.WithDSN("postgres://tempogate:tempogate@"+host+"/tempogate?sslmode=disable"),
		postgres.WithAllowInsecureSSLMode(true),
	)
	require.NoError(t, err, "open state postgres")
	t.Cleanup(func() { _ = store.Close() })
	return store
}
