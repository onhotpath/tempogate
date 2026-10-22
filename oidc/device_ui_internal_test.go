package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStyleHashSource(t *testing.T) {
	// echo -n 'p{}' | openssl dgst -sha256 -binary | base64
	got, err := styleHashSource([]byte("<head><style>p{}</style></head>"))
	require.NoError(t, err)
	assert.Equal(t, "'sha256-gG2yISYereRMiG2lMXrbiUgi0Ubw9p7QCeWcroOvy9Y='", got)

	for name, tmpl := range map[string]string{
		"none": "<head></head>",
		"two":  "<style>a{}</style><style>b{}</style>",
	} {
		_, err := styleHashSource([]byte(tmpl))
		assert.Error(t, err, name)
	}
}
