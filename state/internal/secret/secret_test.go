package secret

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHashIsLowercaseHexSHA256(t *testing.T) {
	require.Equal(t, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", Hash("hello"))
}
