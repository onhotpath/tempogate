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

// stateDBs records the networks that already have a state database, so a
// stack restarted on the same network keeps its state.
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
	if _, started := stateDBs.LoadOrStore(netName, true); !started {
		db, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:          statePostgresImage,
				Env:            map[string]string{"POSTGRES_USER": "tempogate", "POSTGRES_PASSWORD": "tempogate", "POSTGRES_DB": "tempogate"},
				Networks:       []string{netName},
				NetworkAliases: map[string][]string{netName: {"tempogate-db"}},
				WaitingFor: wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		require.NoError(owner, err, "state postgres")
		track(ctx, owner, "tempogate-db", db)
		owner.Cleanup(func() { stateDBs.Delete(netName) })
	}
	env["STATE_DRIVER"] = "postgres"
	env["STATE_POSTGRES_DSN"] = "postgres://tempogate:tempogate@tempogate-db:5432/tempogate?sslmode=disable"
	env["STATE_POSTGRES_ALLOW_INSECURE_SSLMODE"] = "true"
}
