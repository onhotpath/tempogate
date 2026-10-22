package postgres

// This file gives the package's tests real PostgreSQL servers: the ones
// named in TEMPOGATE_TEST_POSTGRES_URLS (CI's service containers), else
// containers started from testImages when Docker is available. Each test
// asks for a fresh database with newDatabase.

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// testURLsEnv lists the servers to test against, comma-separated postgres://
// URLs of a role allowed to CREATE DATABASE. CI sets it to its service
// containers; when it is set no container is started.
const testURLsEnv = "TEMPOGATE_TEST_POSTGRES_URLS"

// testImages are the oldest and newest supported majors, digest-pinned
// (Renovate keeps them current). CI's service containers run the same.
var testImages = []string{
	"postgres:15-alpine@sha256:d2c2ced0372e855e4c257a9e9b5725f403847c01cfb64facbf2b21dbdadb2d74",
	"postgres:18-alpine@sha256:83148c0bc09eac4d598b70a61e1404d0212b76c95c504bfd6c81a4c59ec91792",
}

// testServer is one PostgreSQL server under test.
type testServer struct {
	// Name is "pg" and the major version, for subtest names.
	Name string

	// URL connects to the server's maintenance database.
	URL string
}

var (
	serversOnce sync.Once
	servers     []testServer
	unusable    error
	containers  []testcontainers.Container
)

// testMain runs m and then removes any container the tests started. Call it
// from TestMain.
func testMain(m *testing.M) int {
	code := m.Run()
	for _, c := range containers {
		_ = c.Terminate(context.Background())
	}
	return code
}

// testServers returns every server to test against, starting containers on
// first use. Without testURLsEnv and without Docker it skips t, except in CI,
// where a missing server must fail rather than pass by skipping.
func testServers(t testing.TB) []testServer {
	t.Helper()
	serversOnce.Do(func() { servers, unusable = discover() })
	if unusable != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("no PostgreSQL to test against: %v", unusable)
		}
		t.Skipf("no PostgreSQL to test against (set %s or run Docker): %v", testURLsEnv, unusable)
	}
	return servers
}

func discover() ([]testServer, error) {
	urls := os.Getenv(testURLsEnv)
	if urls == "" {
		var err error
		if urls, err = startContainers(); err != nil {
			return nil, err
		}
	}
	var out []testServer
	for u := range strings.SplitSeq(urls, ",") {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		name, err := serverName(u)
		if err != nil {
			return nil, err
		}
		out = append(out, testServer{Name: name, URL: u})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no server", testURLsEnv)
	}
	return out, nil
}

func startContainers() (string, error) {
	ctx := context.Background()
	var urls []string
	for _, image := range testImages {
		c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
			ContainerRequest: testcontainers.ContainerRequest{
				Image:        image,
				Env:          map[string]string{"POSTGRES_PASSWORD": "postgres"},
				Cmd:          []string{"postgres", "-c", "fsync=off", "-c", "max_connections=300"},
				ExposedPorts: []string{"5432/tcp"},
				WaitingFor: wait.ForLog("database system is ready to accept connections").
					WithOccurrence(2).WithStartupTimeout(2 * time.Minute),
			},
			Started: true,
		})
		if c != nil {
			containers = append(containers, c)
		}
		if err != nil {
			return "", err
		}
		host, err := c.Host(ctx)
		if err != nil {
			return "", err
		}
		port, err := c.MappedPort(ctx, "5432/tcp")
		if err != nil {
			return "", err
		}
		urls = append(urls, (&url.URL{
			Scheme:   "postgres",
			User:     url.UserPassword("postgres", "postgres"),
			Host:     net.JoinHostPort(host, port.Port()),
			Path:     "/postgres",
			RawQuery: "sslmode=disable",
		}).String())
	}
	return strings.Join(urls, ","), nil
}

func serverName(u string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, u)
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close(ctx) }()
	var num int
	if err := conn.QueryRow(ctx, `SELECT current_setting('server_version_num')::int`).Scan(&num); err != nil {
		return "", err
	}
	return fmt.Sprintf("pg%d", num/10000), nil
}

// newDatabase creates an empty database on srv, dropped when t ends, and
// returns its URL. It collates with ICU's en-US, as managed Postgres
// services typically do, so a query that relies on the database's default
// collation where SQLite's bytewise order is meant fails here.
func newDatabase(t testing.TB, srv testServer) string {
	t.Helper()
	name := "t_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	admin := func(sql string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		conn, err := pgx.Connect(ctx, srv.URL)
		if err != nil {
			return err
		}
		defer func() { _ = conn.Close(ctx) }()
		_, err = conn.Exec(ctx, sql)
		return err
	}
	if err := admin(`CREATE DATABASE ` + name + ` TEMPLATE template0 ENCODING 'UTF8' LOCALE_PROVIDER icu ICU_LOCALE 'en-US'`); err != nil {
		t.Fatalf("create test database: %v", err)
	}
	t.Cleanup(func() {
		if err := admin(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`); err != nil {
			t.Errorf("drop test database: %v", err)
		}
	})

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse %s: %v", testURLsEnv, err)
	}
	u.Path = "/" + name
	return u.String()
}

func TestMain(m *testing.M) { os.Exit(testMain(m)) }
