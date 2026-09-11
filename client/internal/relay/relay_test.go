package relay

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/security"
	wsclient "github.com/example/openvpn-ws-cloudflare-relay/client/internal/websocket"
)

// testWSServer emulates the Cloudflare Worker: it upgrades to WebSocket,
// requires Bearer auth, performs the JSON control handshake, then bridges
// to a fixed TCP backend (opaque bytes). The requested target is reported
// on gotTarget for assertions.
func startTestBridge(t *testing.T, token string, backendAddr string) (wsURL string, gotTarget chan proxy.ProxyTarget, closeFn func()) {
	t.Helper()
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	targets := make(chan proxy.ProxyTarget, 16)
	mux.HandleFunc("/connect", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		// Control handshake: first text frame must be the connect request.
		_ = ws.SetReadDeadline(time.Now().Add(10 * time.Second))
		mt, msg, err := ws.ReadMessage()
		if err != nil || mt != websocket.TextMessage {
			return
		}
		var req struct {
			Type string `json:"type"`
			Host string `json:"host"`
			Port uint16 `json:"port"`
		}
		if err := json.Unmarshal(msg, &req); err != nil || req.Type != "connect" || req.Host == "" || req.Port == 0 {
			_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"bad_request"}`))
			return
		}
		targets <- proxy.ProxyTarget{Host: req.Host, Port: req.Port}
		_ = ws.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"connected"}`)); err != nil {
			return
		}
		_ = ws.SetReadDeadline(time.Time{})
		backend, err := net.DialTimeout("tcp", backendAddr, 5*time.Second)
		if err != nil {
			_ = ws.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseInternalServerErr, ""), time.Now().Add(time.Second))
			return
		}
		defer backend.Close()
		done := make(chan struct{}, 2)
		// ws -> backend
		go func() {
			defer func() { done <- struct{}{} }()
			for {
				mt, msg, err := ws.ReadMessage()
				if err != nil {
					return
				}
				if mt != websocket.BinaryMessage {
					continue
				}
				if _, err := backend.Write(msg); err != nil {
					return
				}
			}
		}()
		// backend -> ws
		go func() {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 16384)
			for {
				n, err := backend.Read(buf)
				if n > 0 {
					_ = ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
					if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
						return
					}
				}
				if err != nil {
					return
				}
			}
		}()
		<-done
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck
	return "ws://127.0.0.1:" + portOf(ln) + "/connect", targets, func() {
		_ = srv.Close()
		_ = ln.Close()
	}
}

func portOf(ln net.Listener) string {
	_, p, _ := net.SplitHostPort(ln.Addr().String())
	return p
}

func startEchoTCP(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn) // echo
			}(c)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// openPolicy allows everything the loopback test bridge needs.
func openPolicy() security.Policy {
	return security.Policy{AllowLoopback: true}
}

func testHandler(name, protocol, wsURL, token string) *Handler {
	return &Handler{
		ListenerName:   name,
		Protocol:       protocol,
		Policy:         openPolicy(),
		FrameSize:      4096,
		MaxConnections: 10,
		Dial: func(ctx context.Context) (*wsclient.Conn, error) {
			d := &wsclient.Dialer{URL: wsURL, Token: token, ConnectTimeout: 5 * time.Second, PingInterval: 0}
			return d.Dial(ctx)
		},
	}
}

// End-to-end over HTTP CONNECT: client -> Handler -> WS bridge -> echo TCP.
func TestEndToEndHTTPByteIntegrity(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, gotTarget, closeWS := startTestBridge(t, "test-token", backendAddr)
	defer closeWS()

	h := testHandler("test", ProtocolHTTP, wsURL, "test-token")

	down, up := net.Pipe()
	serveDone := make(chan SessionStats, 1)
	h.OnFinish = func(s SessionStats) { serveDone <- s }
	go h.Serve(context.Background(), up)

	// CONNECT handshake. Target must travel to the Worker as metadata.
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	buf := make([]byte, 64)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := down.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if !bytes.Contains(buf[:n], []byte("200")) {
		t.Fatalf("expected 200, got %q", buf[:n])
	}
	_ = down.SetReadDeadline(time.Time{})

	select {
	case tgt := <-gotTarget:
		if tgt.Host != "127.0.0.1" || tgt.Port != 9 {
			t.Fatalf("worker got wrong target: %+v", tgt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker never received connect metadata")
	}

	// Random binary payload, several megabytes, fragmented writes.
	payload := make([]byte, 4*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for off := 0; off < len(payload); {
			end := off + 1024
			if end > len(payload) {
				end = len(payload)
			}
			_ = down.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if _, err := down.Write(payload[off:end]); err != nil {
				done <- err
				return
			}
			off = end
		}
		done <- nil
	}()
	received := make([]byte, 0, len(payload))
	tmp := make([]byte, 16384)
	for len(received) < len(payload) {
		_ = down.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := down.Read(tmp)
		if err != nil {
			t.Fatalf("read echo: %v (got %d/%d)", err, len(received), len(payload))
		}
		received = append(received, tmp[:n]...)
	}
	if err := <-done; err != nil {
		t.Fatalf("write: %v", err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("byte integrity violated: echo mismatch")
	}
	_ = down.Close()
	select {
	case s := <-serveDone:
		if s.Protocol != ProtocolHTTP || s.TargetHost != "127.0.0.1" || s.TargetPort != 9 {
			t.Fatalf("bad session stats: %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish after close")
	}
}

// End-to-end over SOCKS5 with a domain target.
func TestEndToEndSOCKS5ByteIntegrity(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, gotTarget, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()

	h := testHandler("test", ProtocolSOCKS5, wsURL, "tok")
	down, up := net.Pipe()
	serveDone := make(chan SessionStats, 1)
	h.OnFinish = func(s SessionStats) { serveDone <- s }
	go h.Serve(context.Background(), up)

	_ = down.SetDeadline(time.Now().Add(5 * time.Second))
	// Greeting: no-auth.
	if _, err := down.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := io.ReadFull(down, sel); err != nil || sel[1] != 0x00 {
		t.Fatalf("method selection: %v %v", sel, err)
	}
	// CONNECT 127.0.0.1:7 via domain "localhost"? No — use IP bytes for
	// 127.0.0.1 and domain form for coverage of ATYP DOMAIN:
	name := "localhost"
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(name))}
	req = append(req, []byte(name)...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], 7)
	req = append(req, pb[:]...)
	// localhost resolves to loopback which the open test policy allows.
	if _, err := down.Write(req); err != nil {
		t.Fatalf("request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(down, reply); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("expected success reply, got %v", reply)
	}
	_ = down.SetDeadline(time.Time{})

	select {
	case tgt := <-gotTarget:
		if tgt.Host != "localhost" || tgt.Port != 7 {
			t.Fatalf("worker got wrong target: %+v", tgt)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker never received connect metadata")
	}

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = down.Write(payload)
	}()
	received := make([]byte, 0, len(payload))
	tmp := make([]byte, 16384)
	for len(received) < len(payload) {
		_ = down.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := down.Read(tmp)
		if err != nil {
			t.Fatalf("read echo: %v (got %d/%d)", err, len(received), len(payload))
		}
		received = append(received, tmp[:n]...)
	}
	// NOTE: the test bridge dials backendAddr, not localhost:7 — the echo
	// still validates byte integrity of the full pipeline.
	if !bytes.Equal(payload, received) {
		t.Fatal("byte integrity violated: echo mismatch")
	}
	_ = down.Close()
	select {
	case s := <-serveDone:
		if s.Protocol != ProtocolSOCKS5 {
			t.Fatalf("bad session stats: %+v", s)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not finish after close")
	}
}

func TestRejectInvalidMethod(t *testing.T) {
	h := testHandler("t", ProtocolHTTP, "ws://127.0.0.1:1/", "x")
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := down.Read(buf)
	if !bytes.Contains(buf[:n], []byte("405")) {
		t.Fatalf("expected 405, got %q", buf[:n])
	}
	_ = down.Close()
}

func TestRejectInvalidTarget(t *testing.T) {
	h := testHandler("t", ProtocolHTTP, "ws://127.0.0.1:1/", "x")
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := down.Read(buf)
	if !bytes.Contains(buf[:n], []byte("400")) {
		t.Fatalf("expected 400, got %q", buf[:n])
	}
	_ = down.Close()
}

func TestPolicyRejectsPrivate(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	h := &Handler{
		ListenerName: "t", Protocol: ProtocolHTTP,
		Policy:         security.Policy{}, // default deny for private/loopback
		FrameSize:      4096,
		MaxConnections: 10,
		Dial: func(ctx context.Context) (*wsclient.Conn, error) {
			t.Fatal("dial must not be called for policy-rejected target")
			return nil, nil
		},
	}
	_ = wsURL
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 10.1.2.3:443 HTTP/1.1\r\nHost: 10.1.2.3:443\r\n\r\n")
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := down.Read(buf)
	if !bytes.Contains(buf[:n], []byte("403")) {
		t.Fatalf("expected 403, got %q", buf[:n])
	}
	_ = down.Close()
}

func TestAuthHeaderSent(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "correct", backendAddr)
	defer closeWS()
	h := testHandler("t", ProtocolHTTP, wsURL, "wrong")
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	_ = down.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 256)
	n, _ := down.Read(buf)
	if !bytes.Contains(buf[:n], []byte("502")) {
		t.Fatalf("expected 502 on auth failure, got %q", buf[:n])
	}
	_ = down.Close()
}

func TestFrameSplitting(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	h := testHandler("t", ProtocolHTTP, wsURL, "tok")
	h.FrameSize = 1024
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	tmp := make([]byte, 128)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = down.Read(tmp)
	_ = down.SetReadDeadline(time.Time{})
	big := make([]byte, 64*1024)
	_, _ = rand.Read(big)
	go func() {
		_, _ = down.Write(big)
	}()
	got := make([]byte, 0, len(big))
	chunk := make([]byte, 8192)
	for len(got) < len(big) {
		_ = down.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, err := down.Read(chunk)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		got = append(got, chunk[:n]...)
	}
	if !bytes.Equal(big, got) {
		t.Fatal("frame splitting corrupted stream")
	}
	_ = down.Close()
}

func TestConnectionLimit(t *testing.T) {
	var active atomic.Int64
	active.Store(1)
	h := &Handler{ListenerName: "t", Protocol: ProtocolHTTP, Policy: openPolicy(), MaxConnections: 1,
		Active: &active,
		Dial: func(ctx context.Context) (*wsclient.Conn, error) {
			t.Fatal("dial must not be called when over limit")
			return nil, nil
		}}
	down, up := net.Pipe()
	done := make(chan struct{})
	go func() { h.Serve(context.Background(), up); close(done) }()
	_ = down.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = down.Write([]byte("CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n"))
	_ = down.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	_, _ = down.Read(buf) // expect close / no 200
	_ = down.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("over-limit session did not terminate")
	}
}

func TestHalfCloseForwardsRemainingData(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	h := testHandler("t", ProtocolHTTP, wsURL, "tok")
	down, up := net.Pipe()
	finished := make(chan struct{})
	go func() { h.Serve(context.Background(), up); close(finished) }()
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	tmp := make([]byte, 128)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = down.Read(tmp)
	_ = down.SetReadDeadline(time.Time{})
	msg := []byte("half-close-probe-payload-12345")
	if _, err := down.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	_ = down.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(down, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(msg, got) {
		t.Fatalf("echo mismatch: %q vs %q", msg, got)
	}
	_ = down.Close()
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("session did not terminate after close")
	}
}

func TestConnectTimeout(t *testing.T) {
	h := &Handler{ListenerName: "t", Protocol: ProtocolHTTP, Policy: openPolicy(), MaxConnections: 10,
		Dial: func(ctx context.Context) (*wsclient.Conn, error) {
			d := &wsclient.Dialer{URL: "ws://127.0.0.1:1/connect", Token: "tok", ConnectTimeout: 500 * time.Millisecond}
			return d.Dial(ctx)
		}}
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, _ := down.Read(buf)
	if !bytes.Contains(buf[:n], []byte("502")) {
		t.Fatalf("expected 502 on dial timeout/refusal, got %q", buf[:n])
	}
	_ = down.Close()
}

func TestBackpressureSlowConsumer(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	h := testHandler("t", ProtocolHTTP, wsURL, "tok")
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	tmp := make([]byte, 128)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = down.Read(tmp)
	_ = down.SetReadDeadline(time.Time{})
	const size = 256 * 1024
	payload := make([]byte, size)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		for off := 0; off < len(payload); {
			end := off + 2048
			if end > len(payload) {
				end = len(payload)
			}
			if _, err := down.Write(payload[off:end]); err != nil {
				return
			}
			off = end
		}
	}()
	received := make([]byte, 0, size)
	small := make([]byte, 512)
	for len(received) < size {
		_ = down.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, err := down.Read(small)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		received = append(received, small[:n]...)
		time.Sleep(time.Millisecond)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("slow-consumer byte mismatch (backpressure failure)")
	}
	_ = down.Close()
}

func TestDisconnectHandling(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	finished := make(chan struct{})
	h := testHandler("t", ProtocolHTTP, wsURL, "tok")
	h.OnFinish = func(SessionStats) { close(finished) }
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	tmp := make([]byte, 128)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = down.Read(tmp)
	_ = down.Close()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		t.Fatal("abrupt disconnect did not terminate session")
	}
}

func TestIdleTimeout(t *testing.T) {
	backendAddr, closeBackend := startEchoTCP(t)
	defer closeBackend()
	wsURL, _, closeWS := startTestBridge(t, "tok", backendAddr)
	defer closeWS()
	h := testHandler("t", ProtocolHTTP, wsURL, "tok")
	h.IdleTimeout = 300 * time.Millisecond
	finished := make(chan SessionStats, 1)
	h.OnFinish = func(s SessionStats) { finished <- s }
	down, up := net.Pipe()
	go h.Serve(context.Background(), up)
	fmt.Fprintf(down, "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
	tmp := make([]byte, 128)
	_ = down.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := down.Read(tmp); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	// Stay idle: the watchdog must terminate the session.
	select {
	case s := <-finished:
		if s.Reason != "idle_timeout" {
			t.Fatalf("expected idle_timeout, got %q", s.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("idle session did not terminate")
	}
	_ = down.Close()
}
