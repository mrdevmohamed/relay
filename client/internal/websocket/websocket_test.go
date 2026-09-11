package websocket

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
)

func TestDialAuthFailure(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer good" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		// hold briefly
		time.Sleep(200 * time.Millisecond)
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()
	url := "ws://" + ln.Addr().String() + "/"

	d := &Dialer{URL: url, Token: "bad", ConnectTimeout: 3 * time.Second}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("expected dial error for bad token")
	}
	d2 := &Dialer{URL: url, Token: "good", ConnectTimeout: 3 * time.Second}
	c, err := d2.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial good: %v", err)
	}
	_ = c.Close()
}

func TestDialMissingToken(t *testing.T) {
	d := &Dialer{URL: "ws://127.0.0.1:1/", Token: "", ConnectTimeout: time.Second}
	if _, err := d.Dial(context.Background()); err == nil {
		t.Fatal("expected error for missing token")
	}
}

func TestWriteChunksSplits(t *testing.T) {
	// Echo server counts messages.
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	msgs := make(chan int, 64)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		for {
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				return
			}
			if mt == websocket.BinaryMessage {
				msgs <- len(msg)
				_ = ws.WriteMessage(websocket.BinaryMessage, msg)
			}
		}
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	d := &Dialer{URL: "ws://" + ln.Addr().String() + "/", Token: "x", ConnectTimeout: 3 * time.Second}
	// Token not checked by this server; Dial requires non-empty only.
	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	big := make([]byte, 10*1024)
	if err := c.WriteChunks(big, 1024); err != nil {
		t.Fatalf("WriteChunks: %v", err)
	}
	// Expect 10 messages of 1024.
	total := 0
	for i := 0; i < 10; i++ {
		select {
		case n := <-msgs:
			if n != 1024 {
				t.Fatalf("chunk %d size = %d, want 1024", i, n)
			}
			total += n
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for chunk %d", i)
		}
	}
	if total != 10*1024 {
		t.Fatalf("total = %d", total)
	}
}

func TestHandshakeSuccess(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		mt, msg, err := ws.ReadMessage()
		if err != nil || mt != websocket.TextMessage {
			t.Errorf("expected text connect request: %v %d", err, mt)
			return
		}
		var req ConnectRequest
		if err := json.Unmarshal(msg, &req); err != nil || req.Type != "connect" || req.Host != "example.com" || req.Port != 443 {
			t.Errorf("bad connect request: %s", msg)
			return
		}
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"connected"}`))
		time.Sleep(200 * time.Millisecond)
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	d := &Dialer{URL: "ws://" + ln.Addr().String() + "/", Token: "x", ConnectTimeout: 3 * time.Second}
	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Handshake(ctx, proxy.ProxyTarget{Host: "example.com", Port: 443}); err != nil {
		t.Fatalf("handshake: %v", err)
	}
}

func TestHandshakeRejected(t *testing.T) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer ws.Close()
		_, _, _ = ws.ReadMessage()
		_ = ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"blocked_destination"}`))
		time.Sleep(200 * time.Millisecond)
	})
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	d := &Dialer{URL: "ws://" + ln.Addr().String() + "/", Token: "x", ConnectTimeout: 3 * time.Second}
	c, err := d.Dial(context.Background())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Handshake(ctx, proxy.ProxyTarget{Host: "10.0.0.1", Port: 80}); err == nil {
		t.Fatal("expected handshake rejection")
	}
}
