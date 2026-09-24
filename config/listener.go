package config

import (
	"fmt"
	"net"
	"strconv"
)

// Listener is an IP address and TCP port encoded as host:port.
type Listener struct {
	IP   net.IP
	Port int
}

func (l Listener) String() string {
	if l.IP == nil {
		return net.JoinHostPort("", strconv.Itoa(l.Port))
	}
	return net.JoinHostPort(l.IP.String(), strconv.Itoa(l.Port))
}

func (l Listener) MarshalText() ([]byte, error) {
	return []byte(l.String()), nil
}

func (l *Listener) UnmarshalText(text []byte) error {
	host, port, err := net.SplitHostPort(string(text))
	if err != nil {
		return err
	}
	var ip net.IP
	if host != "" {
		ip = net.ParseIP(host)
		if ip == nil {
			return fmt.Errorf("invalid listener IP address %q", host)
		}
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return fmt.Errorf("invalid listener port %q: %w", port, err)
	}
	*l = Listener{IP: ip, Port: int(p)}
	return nil
}
