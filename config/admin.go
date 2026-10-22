package config

import (
	"net"
	"strconv"
	"strings"
)

// adminAllowedHosts resolves the admin Host allowlist. The default names only
// loopback, whatever the bind: a wildcard bind does not reveal which names
// remote callers will use, and guessing would reopen DNS rebinding.
func adminAllowedHosts(c AdminConfig) []string {
	if strings.TrimSpace(c.AllowedHosts) == "" {
		port := strconv.Itoa(c.Listener.Port)
		return []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("localhost", port),
			net.JoinHostPort("::1", port),
		}
	}
	var hosts []string
	for h := range strings.SplitSeq(c.AllowedHosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
