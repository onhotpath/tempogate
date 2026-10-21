package keys

import (
	"context"
	"fmt"
)

// Init is the boot-flow helper: load all keypairs from the store; if the
// store is empty, generate one and persist it. The in-memory cache is
// populated in CreatedAt-ascending order so Latest returns the most recent.
// Encrypted private keys are decrypted with the KEK (WithEncryptionKey);
// one that cannot be is an error, so serve refuses to start without it.
//
// Init is intentionally separate from the fx graph: long-running commands
// (e.g. serve) opt in by calling Init in their RunE, while one-shot CLIs
// (e.g. keys generate) bypass Init and go straight to Generate.
func (k *Keys) Init(ctx context.Context) error {
	stored, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return fmt.Errorf("keys: load keypairs: %w", err)
	}
	existing, unencrypted, err := k.openStored(stored)
	if err != nil {
		return err
	}

	if len(existing) == 0 {
		kp, err := GenerateKeypair(k.generateOptions()...)
		if err != nil {
			return err
		}
		if err := k.save(ctx, kp); err != nil {
			return err
		}
		existing = []Keypair{kp}
	}

	sortByCreatedAt(existing)

	k.mu.Lock()
	k.keypairs = existing
	k.unencrypted = unencrypted
	k.mu.Unlock()
	return nil
}
