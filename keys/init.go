package keys

import (
	"context"
	"fmt"
)

// Init is the boot-flow helper: load all keypairs from the store; if none is
// active (empty store, or every key retired by hand), generate one and
// persist it so serve never starts without a key to sign with. The in-memory
// cache is populated in CreatedAt-ascending order, which Signing relies on.
// Encrypted private keys are decrypted with the KEK (WithEncryptionKey); one
// that cannot be is an error, so serve refuses to start without it.
//
// Init is intentionally separate from the fx graph: long-running commands
// (e.g. serve) opt in by calling Init in their RunE, while one-shot CLIs
// (e.g. keys generate) bypass Init and go straight to Generate.
//
// With a BootstrapLocker (WithBootstrapLocker) the load and the generation
// run under its lock, so replicas booting together on an empty store agree
// on one key: the first generates it, the others load it.
func (k *Keys) Init(ctx context.Context) error {
	if k.bootstrap != nil {
		return k.bootstrap.LockKeyBootstrap(ctx, k.init)
	}
	return k.init(ctx)
}

func (k *Keys) init(ctx context.Context) error {
	stored, err := k.store.LoadKeypairs(ctx)
	if err != nil {
		return fmt.Errorf("keys: load keypairs: %w", err)
	}
	existing, unencrypted, err := k.openStored(stored)
	if err != nil {
		return err
	}

	sortByCreatedAt(existing)
	if _, ok := k.Signing(existing); !ok {
		kp, err := GenerateKeypair(k.generateOptions()...)
		if err != nil {
			return err
		}
		if err := k.save(ctx, kp); err != nil {
			return err
		}
		existing = append(existing, kp)
	}

	k.swap(existing, unencrypted)
	return nil
}
