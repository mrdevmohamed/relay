package proxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ProxyTarget is the shared abstraction produced by both the HTTP CONNECT
// and SOCKS5 front ends: the hostname (or IP literal) and port the client
// asked for. Relay/session code works only with this type.
type ProxyTarget struct {
	Host string
	Port uint16
}

// String returns "host:port" for logging (never includes secrets; there are
// none in a target).
func (t ProxyTarget) String() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// ParseTarget validates a "host:port" pair from an HTTP CONNECT request line.
// It checks syntax only (non-empty host, numeric port 1-65535); network
// policy (private ranges, domain/port allowlists) is enforced by the
// security package locally and always re-enforced by the Worker.
func ParseTarget(target string) (ProxyTarget, error) {
	host, portStr, err := net.SplitHostPort(strings.TrimSpace(target))
	if err != nil {
		return ProxyTarget{}, fmt.Errorf("invalid target %q: %w", target, err)
	}
	return BuildTarget(host, portStr)
}

// BuildTarget validates an already-split host/port pair (used by SOCKS5,
// which delivers them as separate fields).
func BuildTarget(host, portStr string) (ProxyTarget, error) {
	host = strings.TrimSpace(host)
	// Strip brackets around IPv6 literals ("[::1]" -> "::1").
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	if host == "" {
		return ProxyTarget{}, fmt.Errorf("missing target host")
	}
	if len(host) > 253 {
		return ProxyTarget{}, fmt.Errorf("target host too long")
	}
	portStr = strings.TrimSpace(portStr)
	p, err := strconv.Atoi(portStr)
	if err != nil || p < 1 || p > 65535 {
		return ProxyTarget{}, fmt.Errorf("invalid target port %q: must be 1-65535", portStr)
	}
	return ProxyTarget{Host: host, Port: uint16(p)}, nil
}
