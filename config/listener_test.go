package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestListenerText(t *testing.T) {
	listener := Listener{Port: 8080}
	require.Equal(t, ":8080", listener.String())
	text, err := listener.MarshalText()
	require.NoError(t, err)
	require.Equal(t, ":8080", string(text))

	var decoded Listener
	require.NoError(t, decoded.UnmarshalText(text))
	require.Equal(t, listener, decoded)
}

func TestListenerRejectsMissingPort(t *testing.T) {
	var listener Listener
	require.Error(t, listener.UnmarshalText([]byte("127.0.0.1")))
}
