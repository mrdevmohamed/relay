package websocket

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
)

// Protocol states for the WebSocket control handshake. Normal proxy traffic
// is binary only; control messages are JSON text frames.
type State string

const (
	StateConnecting       State = "CONNECTING"
	StateAuthenticated    State = "AUTHENTICATED"
	StateConnectRequested State = "CONNECT_REQUESTED"
	StateConnected        State = "CONNECTED"
	StateRelaying         State = "RELAYING"
	StateClosing          State = "CLOSING"
	StateClosed           State = "CLOSED"
)

// ConnectRequest is the first message sent after WebSocket establishment.
type ConnectRequest struct {
	Type string `json:"type"`
	Host string `json:"host"`
	Port uint16 `json:"port"`
}

// ConnectResponse is the Worker's reply before binary relaying begins.
type ConnectResponse struct {
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

// Dialer establishes authenticated WSS connections to the Worker.
type Dialer struct {
	URL            string
	Token          string
	ConnectTimeout time.Duration
	PingInterval   time.Duration
}

// Conn is a thin wrapper that owns ping/pong lifecycle.
type Conn struct {
	*websocket.Conn
	pingInterval time.Duration
	stopPing     chan struct{}
}

// Dial connects to the Worker with `Authorization: Bearer <token>`.
// It fails closed on missing token, timeout, or non-101 responses.
func (d *Dialer) Dial(ctx context.Context) (*Conn, error) {
	if d.Token == "" {
		return nil, fmt.Errorf("websocket: missing relay token")
	}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+d.Token)

	dialer := websocket.Dialer{
		HandshakeTimeout: d.ConnectTimeout,
		// Control channel buffer small; data flows via binary messages.
		ReadBufferSize:  32 * 1024,
		WriteBufferSize: 32 * 1024,
	}
	ctx, cancel := context.WithTimeout(ctx, d.ConnectTimeout)
	defer cancel()

	ws, resp, err := dialer.DialContext(ctx, d.URL, header)
	if err != nil {
		if resp != nil {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("websocket dial %s: status=%s: %w", redactURL(d.URL), resp.Status, err)
		}
		return nil, fmt.Errorf("websocket dial %s: %w", redactURL(d.URL), err)
	}
	c := &Conn{Conn: ws, pingInterval: d.PingInterval, stopPing: make(chan struct{})}
	c.startKeepalive()
	return c, nil
}

// startKeepalive handles pong responses (read deadline extension) and sends
// periodic pings on control frames — never inside the data byte stream.
func (c *Conn) startKeepalive() {
	if c.pingInterval <= 0 {
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(c.pingInterval * 3))
	c.SetPongHandler(func(string) error {
		return c.SetReadDeadline(time.Now().Add(c.pingInterval * 3))
	})
	go func() {
		t := time.NewTicker(c.pingInterval)
		defer t.Stop()
		for {
			select {
			case <-c.stopPing:
				return
			case <-t.C:
				_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := c.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second)); err != nil {
					return
				}
			}
		}
	}()
}

// Close shuts down keepalive and the underlying connection.
func (c *Conn) Close() error {
	select {
	case <-c.stopPing:
	default:
		close(c.stopPing)
	}
	return c.Conn.Close()
}

// Handshake sends the JSON connect request for target and waits for the
// Worker's "connected" control response. Binary relaying may only begin
// after this returns nil. The control exchange uses text frames; payload
// traffic always uses binary frames.
func (c *Conn) Handshake(ctx context.Context, target proxy.ProxyTarget) error {
	req, err := json.Marshal(ConnectRequest{Type: "connect", Host: target.Host, Port: target.Port})
	if err != nil {
		return fmt.Errorf("websocket: encode connect request: %w", err)
	}
	_ = c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := c.WriteMessage(websocket.TextMessage, req); err != nil {
		return fmt.Errorf("websocket: send connect request: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("websocket: handshake: %w", ctx.Err())
		default:
		}
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		mt, msg, err := c.ReadMessage()
		if err != nil {
			return fmt.Errorf("websocket: read connect response: %w", err)
		}
		if mt != websocket.TextMessage {
			continue // ignore stray binary/control frames during handshake
		}
		var resp ConnectResponse
		if err := json.Unmarshal(msg, &resp); err != nil {
			return fmt.Errorf("websocket: invalid connect response")
		}
		switch resp.Type {
		case "connected":
			return nil
		case "error":
			if resp.Code != "" {
				return fmt.Errorf("websocket: worker rejected target (%s)", resp.Code)
			}
			return fmt.Errorf("websocket: worker rejected target")
		default:
			return fmt.Errorf("websocket: unexpected control message %q", resp.Type)
		}
	}
}

// WriteChunks splits p into bounded binary messages of at most frameSize.
// This preserves byte order while bounding memory per message.
func (c *Conn) WriteChunks(p []byte, frameSize int) error {
	if frameSize <= 0 {
		frameSize = 16384
	}
	for len(p) > 0 {
		n := len(p)
		if n > frameSize {
			n = frameSize
		}
		_ = c.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if err := c.WriteMessage(websocket.BinaryMessage, p[:n]); err != nil {
			return err
		}
		p = p[n:]
	}
	return nil
}

func redactURL(u string) string {
	// Never include query strings (which must not carry secrets anyway).
	for i, r := range u {
		if r == '?' {
			return u[:i]
		}
	}
	return u
}
