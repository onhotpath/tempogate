package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// tokenFileName / tokenDirName compose the default on-disk location,
// ~/.tempogate/token.json. The directory is created 0700 and the file 0600 so
// the bearer token is never group/world readable.
const (
	tokenDirName  = ".tempogate"
	tokenFileName = "token.json"
	tokenDirPerm  = 0o700
	tokenFilePerm = 0o600
)

// ErrNoToken is returned by Load when the token file does not exist yet — the
// engineer has not run `tempogate login`. It is distinct from a corrupt-file
// error so the caller can print the right next step rather than a parse dump.
var ErrNoToken = errors.New("cli: no token file; run `tempogate login` first")

// Token is the persisted credential set: the bearer access token, the opaque
// refresh token that renews it, the access token's absolute expiry, and the
// client_id both were issued to. It is the single shape produced by login,
// written to disk, and renewed by EnsureFresh, so the three never drift
// apart. ClientID is kept because the issuer only honours a refresh token for
// the client it was issued to, and the loopback and device flows log in as
// different clients.
type Token struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	ClientID     string    `json:"client_id,omitempty"`
}

// DefaultTokenPath is ~/.tempogate/token.json. It is resolved lazily (not a
// const) because the home directory is only known at runtime and differs per
// machine; callers pass an explicit path in tests.
func DefaultTokenPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cli: resolve home directory: %w", err)
	}
	return filepath.Join(home, tokenDirName, tokenFileName), nil
}

// Save writes tok to path with 0600 perms, creating the parent directory 0700.
// The write is atomic: it lands in a temp file in the same directory (so the
// rename cannot cross filesystems) which is then renamed over path, so a
// crash mid-write never leaves a truncated token file a reader could trip on.
func Save(path string, tok Token) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, tokenDirPerm); err != nil {
		return fmt.Errorf("cli: create token dir: %w", err)
	}

	// #nosec G117 -- persisting the engineer's own bearer/refresh token to a
	// 0600 file is this command's entire purpose; the "secret" is being
	// deliberately written by its owner, not leaked into logs or telemetry.
	data, err := json.MarshalIndent(tok, "", "  ")
	if err != nil {
		return fmt.Errorf("cli: encode token: %w", err)
	}

	tmp, err := os.CreateTemp(dir, tokenFileName+".*")
	if err != nil {
		return fmt.Errorf("cli: create temp token file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }() // no-op once the rename succeeds

	if err := tmp.Chmod(tokenFilePerm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cli: chmod temp token file: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("cli: write temp token file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("cli: close temp token file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("cli: replace token file: %w", err)
	}
	return nil
}

// Load reads and decodes the token file. A missing file is reported as
// ErrNoToken (the caller should suggest `tempogate login`); any other problem
// — unreadable, malformed JSON — is returned verbatim so it is not mistaken
// for "not logged in".
func Load(path string) (Token, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is the user's own token file (default ~/.tempogate or an explicit --token-file), not attacker-controlled input
	if errors.Is(err, os.ErrNotExist) {
		return Token{}, ErrNoToken
	}
	if err != nil {
		return Token{}, fmt.Errorf("cli: read token file: %w", err)
	}

	var tok Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return Token{}, fmt.Errorf("cli: decode token file %s: %w", path, err)
	}
	return tok, nil
}
