package security

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
)

func tgt(host string, port uint16) proxy.ProxyTarget {
	return proxy.ProxyTarget{Host: host, Port: port}
}

func TestBlocksPrivateIPv4(t *testing.T) {
	p := Policy{}
	ctx := context.Background()
	for _, h := range []string{"10.1.2.3", "172.16.5.4", "172.31.255.1", "192.168.1.1"} {
		if err := p.ValidateTarget(ctx, tgt(h, 443)); err == nil {
			t.Fatalf("expected %s to be blocked", h)
		}
	}
}

func TestBlocksLoopback(t *testing.T) {
	p := Policy{}
	ctx := context.Background()
	for _, h := range []string{"127.0.0.1", "::1", "localhost"} {
		if err := p.ValidateTarget(ctx, tgt(h, 443)); err == nil {
			t.Fatalf("expected %s to be blocked", h)
		}
	}
}

func TestAllowsLoopbackWhenEnabled(t *testing.T) {
	p := Policy{AllowLoopback: true}
	ctx := context.Background()
	if err := p.ValidateTarget(ctx, tgt("127.0.0.1", 8080)); err != nil {
		t.Fatalf("loopback should be allowed: %v", err)
	}
	// Private ranges stay blocked.
	if err := p.ValidateTarget(ctx, tgt("10.0.0.1", 80)); err == nil {
		t.Fatal("private should still be blocked")
	}
}

func TestBlocksLinkLocalAndMetadata(t *testing.T) {
	p := Policy{AllowLoopback: true}
	ctx := context.Background()
	for _, h := range []string{"169.254.169.254", "fe80::1", "metadata.google.internal"} {
		if err := p.ValidateTarget(ctx, tgt(h, 80)); err == nil {
			t.Fatalf("expected %s to be blocked", h)
		}
	}
}

func TestBlocksMulticastAndBroadcast(t *testing.T) {
	p := Policy{}
	ctx := context.Background()
	for _, h := range []string{"224.0.0.1", "255.255.255.255", "0.0.0.0", "ff02::1"} {
		if err := p.ValidateTarget(ctx, tgt(h, 80)); err == nil {
			t.Fatalf("expected %s to be blocked", h)
		}
	}
}

func TestPortPolicy(t *testing.T) {
	p := Policy{AllowLoopback: true}
	ctx := context.Background()
	if err := p.ValidateTarget(ctx, tgt("127.0.0.1", 0)); err == nil {
		t.Fatal("port 0 must be blocked")
	}
	if err := p.ValidateTarget(ctx, tgt("127.0.0.1", 25)); err == nil {
		t.Fatal("port 25 must be blocked")
	}
	p2 := Policy{AllowLoopback: true, AllowedPorts: []int{443, 8443}}
	if err := p2.ValidateTarget(ctx, tgt("127.0.0.1", 443)); err != nil {
		t.Fatalf("443 should be allowed: %v", err)
	}
	if err := p2.ValidateTarget(ctx, tgt("127.0.0.1", 80)); err == nil {
		t.Fatal("80 should be blocked by allowed_ports")
	}
}

func TestDomainLists(t *testing.T) {
	// Hermetic: localhost resolves locally everywhere; allowlisting it must
	// admit it (with loopback allowed).
	p := Policy{AllowedDomains: []string{"localhost"}, AllowLoopback: true}
	ctx := context.Background()
	if err := p.ValidateTarget(ctx, tgt("localhost", 443)); err != nil {
		t.Fatalf("allowed domain rejected: %v", err)
	}
	if err := p.ValidateTarget(ctx, tgt("other.org", 443)); err == nil {
		t.Fatal("non-allowlisted domain should be rejected")
	}
	pb := Policy{BlockedDomains: []string{"bad.example"}, AllowLoopback: true}
	if err := pb.ValidateTarget(ctx, tgt("sub.bad.example", 443)); err == nil {
		t.Fatal("blocked subdomain should be rejected")
	}
	if err := pb.ValidateTarget(ctx, tgt("bad.example", 443)); err == nil {
		t.Fatal("blocked exact domain should be rejected")
	}
}

func TestAllowsPublicIP(t *testing.T) {
	p := Policy{}
	ctx := context.Background()
	if err := p.ValidateTarget(ctx, tgt("93.184.216.34", 443)); err != nil {
		t.Fatalf("public IP should pass: %v", err)
	}
}

func TestResolutionFailureAllows(t *testing.T) {
	// Local DNS may be censored, hijacked, or slow while edge DNS works.
	// The Worker still enforces name policy, so fail open here.
	p := Policy{
		LookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return nil, fmt.Errorf("lookup %s: i/o timeout", host)
		},
	}
	ctx := context.Background()
	if err := p.ValidateTarget(ctx, tgt("public-vpn-236.opengw.net", 443)); err != nil {
		t.Fatalf("resolution failure should fail open, got: %v", err)
	}
}

func TestResolvedAddressesEnforced(t *testing.T) {
	ctx := context.Background()
	priv := Policy{
		LookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("10.9.9.9")}}, nil
		},
	}
	if err := priv.ValidateTarget(ctx, tgt("rebind.example", 443)); err == nil {
		t.Fatal("resolved private address must be blocked (DNS-rebinding protection)")
	}
	pub := Policy{
		LookupIPAddr: func(ctx context.Context, host string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("93.184.216.34")}}, nil
		},
	}
	if err := pub.ValidateTarget(ctx, tgt("example.com", 443)); err != nil {
		t.Fatalf("resolved public address should pass: %v", err)
	}
}
