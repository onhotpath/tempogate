package keys

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/fx"
)

func graceGraph(grace time.Duration, populate any) *fx.App {
	return fx.New(
		fx.NopLogger,
		fx.Provide(func() KeyStore { return &fakeKeyStore{} }),
		fx.Supply(fx.Annotate(grace, fx.ResultTags(`name:"keys_retirement_grace"`))),
		fx.Provide(newFx),
		fx.Populate(populate),
	)
}

func TestFxAppliesRetirementGrace(t *testing.T) {
	var k *Keys
	app := graceGraph(time.Minute, &k)
	require.NoError(t, app.Err())
	require.Equal(t, time.Minute, k.grace)
}

func TestFxRejectsNegativeRetirementGrace(t *testing.T) {
	var k *Keys
	app := graceGraph(-time.Second, &k)
	require.ErrorContains(t, app.Err(), "KEYS_RETIREMENT_GRACE")
}
