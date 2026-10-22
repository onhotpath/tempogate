// Package state documents the state-store contract. It holds no code: every
// consumer defines the narrow interface it needs in its own package, and a
// backend satisfies them all: state/sqlite (the default, one replica) and
// state/postgres (any number of replicas over one database), selected by
// STATE_DRIVER. No package imports state/. The contract below is what any
// backend must guarantee, whether it runs as one process or as N replicas
// over a shared database; state/storetest is the conformance suite that
// checks it, and every backend runs it in CI.
//
// # Interfaces and where they live
//
// Each backend's Fx (sqlite.Fx, postgres.Fx) binds its *Store with fx.As to:
//
//   - keys.KeyStore: signing keypairs (SaveKeypair, LoadKeypairs, RetireKeypair).
//   - keys.DenylistChecker: the integration-key jti denylist (IsRevoked).
//   - keys.ChangeFeed: optional change notifications, see below.
//   - oidc.AuthRequestStore and oidc.CallbackStore: pending /authorize
//     requests and the authorization codes minted at the callback.
//   - oidc.TokenStore: code redemption and the refresh-token lifecycle.
//   - oidc.DeviceCodeStore: the RFC 8628 device flow.
//   - oidc.BrowserSessionStore: verification-page sessions.
//   - api.StoreProbe: readiness.
//
// and provides admin.KeyRegistry and admin.SessionStore through adapters
// (NewAdminKeyRegistry, NewAdminSessionStore in each backend), because their
// short method names would collide on one struct. keys.PrivateKeyRewriter
// (`tempogate keys encrypt`) is satisfied by every *Store as well. A backend
// shared by several processes also binds keys.BootstrapLocker, so replicas
// booting together on an empty database generate one signing key.
//
// The server subcommands (cmd/servercmd) reach a backend only through those
// interfaces and their own small seam over the *Store (Ping, IsCurrent,
// Migrate) and its Reaper. Schema migration and the expired-row reaper are
// per backend, outside this contract, but follow the same rules: Migrate is
// safe to run concurrently and repeatedly, IsCurrent reports the same
// operator-facing messages (state/internal/migration), and the reaper
// deletes only rows every reader already refuses. Rate limiting is not a
// store concern at all: it belongs to whatever implements it, decoupled
// from state.
//
// The method docs on each interface state its behaviour; the rules below
// apply to all of them.
//
// # The application owns the clock
//
// Every time a store writes or compares is a parameter the caller passes
// (an `at` or `now` argument, or a field such as CreatedAt and ExpiresAt).
// SQL never reads the database clock: no now(), CURRENT_TIMESTAMP,
// datetime('now') or similar, not even as a column DEFAULT. Expiry is judged
// against the caller's time, or left to the caller where a method says so.
// This keeps replicas, backends and tests in agreement, and lets a fake
// clock drive every path. storetest.CheckNoSQLClock enforces it on a
// backend's source.
//
// Times are UTC. A store keeps them to the microsecond or finer and returns
// the same instant (time.Equal); it may truncate below a microsecond, so
// callers never rely on nanoseconds surviving a round trip. The application
// clock (internal/clock.Now) is truncated to the microsecond at the source,
// so in practice every time round-trips exactly and a comparison made in Go
// agrees with one made in SQL, on every backend.
//
// # Atomicity and concurrency
//
// A store is safe for concurrent use, by goroutines and by other processes
// or replicas sharing the same database. Each method is atomic: it commits
// entirely or not at all, and concurrent calls behave as if run one after
// another. In particular:
//
//   - Consume-once: of any number of concurrent ConsumeAuthRequest,
//     ConsumeAuthCode, ConsumeRefresh or ConsumeDeviceCode calls on one
//     value, exactly one succeeds. The others get the method's not-found
//     sentinel, or, where the consumed row stays as a tombstone (auth codes,
//     refresh tokens), its reuse sentinel together with the row.
//   - Conditional transitions: ApproveDeviceCode and DenyDeviceCode decide a
//     pending code once; RetireKeypair never leaves zero active keypairs, even
//     when the last two are retired concurrently; MarkRevoked and
//     RevokeRefreshFamily stamp once and keep the first time.
//   - Device polling: of concurrent PollDeviceCode calls on a code not polled
//     within its interval, exactly one is well paced; every other one is
//     slow_down and raises the interval by 5 seconds.
//   - Refresh families: no live token survives in a revoked family, however
//     a rotation (ConsumeRefresh then SaveRefresh) interleaves with a
//     revocation. SaveRefresh into a revoked family returns
//     oidc.ErrRefreshFamilyRevoked, and a child saved just before the
//     revocation is revoked with it. Under SQLite's single writer this is
//     one guarded INSERT; Postgres, at READ COMMITTED, takes the family's
//     refresh_families row FOR SHARE on rotation and updates it first on
//     revocation, because the guarded INSERT alone is write skew there.
//   - Duplicates: saving a row whose key exists fails and leaves the existing
//     row unchanged. Device codes report oidc.ErrDuplicateDeviceCode so the
//     issuer can regenerate; the other keys are 256-bit random values, so any
//     error is acceptable.
//
// # Ordering
//
// LoadKeypairs returns keypairs by created_at, then kid. KeyRegistry.List
// returns integration keys by id descending (UUIDv7, so newest first),
// limit+1 rows. SessionStore.List returns live sessions by email, then
// auth_time. Nothing else promises an order.
//
// Text orders and compares bytewise, as SQLite does, never by a database
// locale: "Zoe" sorts before "bob", and both before "émile". Where an email
// matches case-insensitively (SessionStore.List, RevokeEmail), only the
// ASCII letters A-Z fold; every other byte must match exactly.
//
// # Errors
//
// Not-found, reuse and conflict outcomes are the consumer packages'
// sentinels (oidc.ErrAuthCodeNotFound, oidc.ErrRefreshReused,
// admin.ErrSessionNotFound, keys.ErrLastActiveKeypair and so on), matched with
// errors.Is; a backend may wrap them. An error never carries the value a row
// was looked up by: codes, tokens, session ids and states are bearer
// secrets, and error text ends up in logs. Refresh tokens, authorization and
// device codes and verification-page session ids are stored only as their
// SHA-256, so a copy of the database holds nothing a client could present.
//
// # Change notifications
//
// keys.ChangeFeed lets a store tell this process that keypairs changed or a
// jti was revoked, so keys.Keys.Watch reloads and keys.DenylistCache.Follow
// hydrates at once. It is optional and best-effort: a change is delivered
// only after its write commits, but may be dropped, coalesced, duplicated or
// spurious, and a backend may not offer the feed at all. Correctness never
// depends on it. Every replica still reloads keys every KEYS_RELOAD_INTERVAL,
// signs with a new key only after KEYS_PUBLISH_DELAY, and lets a cached
// denylist answer live for at most DefaultDenylistTTL; the feed only
// shortens those waits.
//
// SQLite implements the feed in process: it fans out the changes written
// through the same *sqlite.Store and never sees another process's writes
// (`tempogate keys generate` next to a running `serve` is still picked up by
// the periodic reload, as before). That is all a single-writer file can
// offer. Postgres sends a NOTIFY in the writing transaction, for key writes
// and integration-key revocations only (never on the token path), and each
// replica relays what its one LISTEN connection receives; after every
// reconnect it re-reports what it may have missed (see
// postgres.Store.SubscribeChanges).
//
// # Adding a consumer
//
//  1. Define the interface in your package with the method names that read
//     best there, and document its behaviour in the method docs.
//  2. Implement it on every backend's *Store under domain-prefixed names
//     (SaveFoo, FooByID, ...) so consumers do not collide on one struct.
//  3. Bind it in each backend's fx.go: fx.As(new(YourInterface)) when the
//     names match, an adapter constructor when they do not (see
//     admin_adapter.go).
//  4. Add its behaviour to state/storetest, so every backend is held to it.
package state
