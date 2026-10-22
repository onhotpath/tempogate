// Package clock is the application's wall clock. The application owns the
// clock (state/doc.go): every time a state store writes or compares comes
// from here, or from a test's fake.
package clock

import "time"

// Now is the current time in UTC, truncated to the microsecond: the
// precision every state backend keeps. A time taken from Now therefore
// survives a round trip through SQLite or Postgres unchanged, and compares
// the same in Go as in either database.
func Now() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }
