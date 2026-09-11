package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const validCfg = `
listen:
  http: "127.0.0.1:8080"
  socks5: "127.0.0.1:1080"
websocket:
  url: "wss://proxy.example.com/connect"
  token: "${RELAY_TOKEN}"
relay:
  frame_size: 16384
  connect_timeout: 10s
  idle_timeout: 10m
  ping_interval: 30s
  max_connections: 100
tcp:
  keepalive: 30s
  tcp_nodelay: true
logging:
  level: info
  format: json
management:
  address: "127.0.0.1:9090"
`

func TestLoadValid(t *testing.T) {
	t.Setenv("RELAY_TOKEN", "secret123")
	p := writeTemp(t, validCfg)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Websocket.Token != "secret123" {
		t.Fatalf("env expansion failed: %q", c.Websocket.Token)
	}
	if c.Relay.FrameSize != 16384 {
		t.Fatalf("frame_size = %d", c.Relay.FrameSize)
	}
	if deref(c.Listen.HTTP) != "127.0.0.1:8080" || deref(c.Listen.SOCKS5) != "127.0.0.1:1080" {
		t.Fatalf("listen = %+v", c.Listen)
	}
}

func TestRejectMissingToken(t *testing.T) {
	p := writeTemp(t, `
listen:
  http: "127.0.0.1:8080"
websocket:
  url: "wss://proxy.example.com/connect"
  token: ""
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestRejectNoListeners(t *testing.T) {
	p := writeTemp(t, `
listen:
  http: ""
  socks5: ""
websocket:
  url: "wss://proxy.example.com/connect"
  token: "x"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error when both listeners are disabled")
	}
}

func TestRejectPlainWSNonLoopback(t *testing.T) {
	p := writeTemp(t, `
listen:
  http: "127.0.0.1:8080"
websocket:
  url: "ws://evil.example.com/connect"
  token: "x"
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for non-TLS ws:// to non-loopback")
	}
}

func TestRejectBadSocksAuth(t *testing.T) {
	p := writeTemp(t, `
listen:
  socks5: "127.0.0.1:1080"
websocket:
  url: "wss://proxy.example.com/connect"
  token: "x"
socks5:
  auth:
    mode: "password"
    username: ""
`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected error for password mode without username")
	}
}

func TestDefaults(t *testing.T) {
	p := writeTemp(t, `
websocket:
  url: "wss://proxy.example.com/connect"
  token: "x"
`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.Relay.FrameSize != DefaultFrameSize {
		t.Fatalf("default frame_size = %d", c.Relay.FrameSize)
	}
	if c.Management.Address != DefaultManagementAddr {
		t.Fatalf("default management = %q", c.Management.Address)
	}
	if deref(c.Listen.HTTP) != DefaultHTTPAddr || deref(c.Listen.SOCKS5) != DefaultSOCKS5Addr {
		t.Fatalf("default listen = %+v", c.Listen)
	}
}
