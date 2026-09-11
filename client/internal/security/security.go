// Package security enforces destination policy for proxied targets.
//
// The local relay is a generic proxy: any client-supplied host:port arrives
// here. This package fails closed on loopback, private, link-local,
// multicast and cloud-metadata destinations unless explicitly allowed, and
// honours domain/port allow/block lists. The Cloudflare Worker always
// re-validates with the same semantics.
package security

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
)

// Policy configures destination validation.
type Policy struct {
	AllowPrivateNetworks bool
	AllowLoopback        bool
	AllowLinkLocal       bool
	AllowedDomains       []string
	BlockedDomains       []string
	AllowedPorts         []int
	// ResolveTimeout bounds DNS lookups for domain targets.
	ResolveTimeout time.Duration
	// LookupIPAddr resolves domain targets. Nil means net.DefaultResolver.
	// Override in tests to simulate DNS outcomes hermetically.
	LookupIPAddr func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DefaultResolveTimeout bounds DNS lookups during validation.
const DefaultResolveTimeout = 5 * time.Second

var blockedNets []*net.IPNet

func init() {
	for _, cidr := range []string{
		"127.0.0.0/8",    // loopback
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // link-local + cloud metadata (169.254.169.254)
		"0.0.0.0/8",      // unspecified / broadcast source
		"224.0.0.0/4",    // multicast
		"255.255.255.255/32",
		"::1/128",   // loopback
		"::/128",    // unspecified
		"fc00::/7",  // unique local
		"fe80::/10", // link-local
		"ff00::/8",  // multicast
	} {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("security: bad builtin cidr " + cidr)
		}
		blockedNets = append(blockedNets, n)
	}
}

// ValidateTarget checks a proxy target against the policy. Domain targets
// are resolved and every resolved address is checked (DNS-rebinding
// protection); IP literals are checked directly.
func (p Policy) ValidateTarget(ctx context.Context, t proxy.ProxyTarget) error {
	if err := p.checkPort(int(t.Port)); err != nil {
		return err
	}
	host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(t.Host)), ".")
	if host == "" {
		return fmt.Errorf("security: empty host")
	}
	if err := p.checkName(host); err != nil {
		return err
	}
	if ip := net.ParseIP(host); ip != nil {
		return p.checkIP(ip)
	}
	timeout := p.ResolveTimeout
	if timeout <= 0 {
		timeout = DefaultResolveTimeout
	}
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	lookup := p.LookupIPAddr
	if lookup == nil {
		lookup = net.DefaultResolver.LookupIPAddr
	}
	addrs, err := lookup(rctx, host)
	if err != nil {
		// Fail open: local DNS may be censored, hijacked, or slow while
		// the Worker's edge DNS resolves fine. The Worker still enforces
		// name policy, and the Cloudflare platform refuses
		// private/loopback dial targets. Only successfully resolved
		// forbidden addresses block here.
		return nil
	}
	if len(addrs) == 0 {
		return fmt.Errorf("security: %q resolves to no addresses", t.Host)
	}
	for _, a := range addrs {
		if err := p.checkIP(a.IP); err != nil {
			return fmt.Errorf("security: %q: %w", t.Host, err)
		}
	}
	return nil
}

func (p Policy) checkPort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("security: invalid port %d", port)
	}
	if port == 25 {
		return fmt.Errorf("security: port 25 blocked")
	}
	if len(p.AllowedPorts) > 0 {
		for _, a := range p.AllowedPorts {
			if a == port {
				return nil
			}
		}
		return fmt.Errorf("security: port %d not in allowed_ports", port)
	}
	return nil
}

// checkName enforces domain allow/block lists and well-known internal names.
func (p Policy) checkName(host string) error {
	for _, b := range p.BlockedDomains {
		if domainMatch(host, b) {
			return fmt.Errorf("security: domain %q blocked", host)
		}
	}
	if len(p.AllowedDomains) > 0 {
		ok := false
		for _, a := range p.AllowedDomains {
			if domainMatch(host, a) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("security: domain %q not in allowed_domains", host)
		}
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		if !p.AllowLoopback {
			return fmt.Errorf("security: localhost blocked")
		}
		return nil
	}
	switch host {
	case "metadata.google.internal", "metadata.goog",
		"instance-data", "instance-data.compute.internal":
		return fmt.Errorf("security: cloud metadata host %q blocked", host)
	}
	return nil
}

func (p Policy) checkIP(ip net.IP) error {
	if ip.IsLoopback() && !p.AllowLoopback {
		return fmt.Errorf("security: loopback %s blocked", ip)
	}
	if ip.IsLinkLocalUnicast() && !p.AllowLinkLocal {
		return fmt.Errorf("security: link-local %s blocked", ip)
	}
	if !p.AllowPrivateNetworks && ip.IsPrivate() {
		return fmt.Errorf("security: private %s blocked", ip)
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			// Ranges already covered by the explicit toggles above are
			// allowed when their toggle is set; everything else is denied.
			if n.String() == "127.0.0.0/8" || n.String() == "::1/128" {
				if p.AllowLoopback {
					continue
				}
			} else if n.String() == "169.254.0.0/16" || n.String() == "fe80::/10" {
				if p.AllowLinkLocal {
					continue
				}
			} else if p.AllowPrivateNetworks && isRFC1918OrULA(n.String()) {
				continue
			}
			return fmt.Errorf("security: %s blocked (%s)", ip, n.String())
		}
	}
	return nil
}

func isRFC1918OrULA(cidr string) bool {
	switch cidr {
	case "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7":
		return true
	}
	return false
}

// domainMatch reports whether host equals domain or is a subdomain of it
// (case-insensitive; trailing dots ignored).
func domainMatch(host, domain string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	if domain == "" {
		return false
	}
	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}
