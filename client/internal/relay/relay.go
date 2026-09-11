package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/security"
	wsclient "github.com/example/openvpn-ws-cloudflare-relay/client/internal/websocket"
)

// Protocols served by the local relay.
const (
	ProtocolHTTP   = "http"
	ProtocolSOCKS5 = "socks5"
)

// SessionStats carries per-connection accounting (metadata only, no payload).
type SessionStats struct {
	ID            string
	Listener      string
	Protocol      string // "http" or "socks5"
	ClientAddress string
	TargetHost    string
	TargetPort    uint16
	WorkerURL     string
	StartTime     time.Time
	Duration      time.Duration
	BytesTCPToWS  int64
	BytesWSToTCP  int64
	Reason        string
}

// Handler bridges one accepted downstream TCP connection to one Worker
// WebSocket session. The byte stream is opaque: no parsing, no inspection,
// no modification beyond the front-end handshake.
type Handler struct {
	ListenerName string
	Protocol     string // ProtocolHTTP or ProtocolSOCKS5
	// Dial establishes the Worker WebSocket (authenticated, pre-handshake).
	Dial func(ctx context.Context) (*wsclient.Conn, error)
	// Policy validates the client-requested destination locally. The
	// Worker always re-validates.
	Policy           security.Policy
	FrameSize        int
	IdleTimeout      time.Duration
	MaxSession       time.Duration // 0 = unlimited
	MaxConnections   int
	Active           *atomic.Int64 // shared active-session counter (nil allowed)
	Logger           *slog.Logger
	SocksCredentials proxy.Socks5Credentials

	OnFinish func(SessionStats)
}

// Serve handles a single downstream TCP connection: front-end handshake,
// policy check, WebSocket dial + control handshake, then transparent
// bidirectional streaming. It always closes conn.
func (h *Handler) Serve(ctx context.Context, conn net.Conn) {
	start := time.Now()
	id := fmt.Sprintf("%d-%s", start.UnixNano(), conn.RemoteAddr())
	log := h.Logger
	if log == nil {
		log = slog.Default()
	}
	stats := SessionStats{
		ID:            id,
		Listener:      h.ListenerName,
		Protocol:      h.Protocol,
		ClientAddress: conn.RemoteAddr().String(),
		StartTime:     start,
		Reason:        "ok",
	}

	if h.Active != nil {
		cur := h.Active.Add(1)
		defer h.Active.Add(-1)
		if h.MaxConnections > 0 && cur > int64(h.MaxConnections) {
			stats.Reason = "connection_limit"
			h.finish(conn, nil, stats, start, 0, 0)
			log.Warn("relay: connection limit exceeded", "connection_id", id)
			return
		}
	}

	// --- Phase 1: front-end handshake (short deadlines; raw stream afterwards).
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	target, handshakeErr := h.acceptDownstream(conn)
	if handshakeErr != nil {
		stats.Reason = "bad_request: " + shortErr(handshakeErr.err)
		if handshakeErr.responded {
			h.finish(conn, nil, stats, start, 0, 0)
		} else {
			h.finish(conn, nil, stats, start, 0, 0)
		}
		log.Info("relay: reject proxy request",
			"connection_id", id,
			"client_address", stats.ClientAddress, "reason", stats.Reason)
		return
	}
	stats.TargetHost = target.Host
	stats.TargetPort = target.Port

	// --- Phase 2: local destination policy (Worker re-validates).
	if err := h.Policy.ValidateTarget(ctx, target); err != nil {
		stats.Reason = "forbidden: " + shortErr(err)
		h.denyDownstream(conn)
		h.finish(conn, nil, stats, start, 0, 0)
		log.Info("relay: reject proxy destination",
			"connection_id", id,
			"client_address", stats.ClientAddress,
			"target", target.String(), "reason", stats.Reason)
		return
	}

	// --- Phase 3: establish WSS to Worker, then control handshake.
	ws, err := h.Dial(ctx)
	if err != nil {
		stats.Reason = "bad_gateway: " + shortErr(err)
		h.failDownstream(conn)
		h.finish(conn, nil, stats, start, 0, 0)
		log.Warn("relay: worker dial failed",
			"connection_id", id, "reason", stats.Reason)
		return
	}
	hsCtx, hsCancel := context.WithTimeout(ctx, 15*time.Second)
	hserr := ws.Handshake(hsCtx, target)
	hsCancel()
	if hserr != nil {
		stats.Reason = "bad_gateway: " + shortErr(hserr)
		h.failDownstream(conn)
		h.finish(conn, ws, stats, start, 0, 0)
		log.Warn("relay: worker handshake failed",
			"connection_id", id,
			"target", target.String(), "reason", stats.Reason)
		return
	}

	// Handshake done: clear deadlines (streaming uses its own), answer the
	// downstream client, then forward raw bytes.
	_ = conn.SetDeadline(time.Time{})
	if err := h.acceptedDownstream(conn); err != nil {
		stats.Reason = "proxy_write_failed"
		h.finish(conn, ws, stats, start, 0, 0)
		return
	}

	t2w, w2t, reason := Bridge(ctx, conn, ws, PumpConfig{
		FrameSize:   h.FrameSize,
		IdleTimeout: h.IdleTimeout,
		MaxSession:  h.MaxSession,
	})
	stats.Reason = reason
	h.finish(conn, ws, stats, start, t2w, w2t)
	log.Info("relay: session closed",
		"connection_id", id,
		"client_address", stats.ClientAddress, "target", target.String(),
		"duration", time.Since(start).String(),
		"bytes_tcp_to_ws", t2w, "bytes_ws_to_tcp", w2t,
		"termination_reason", reason)
}

type acceptError struct {
	err       error
	responded bool
}

// acceptDownstream runs the protocol handshake and returns the target.
func (h *Handler) acceptDownstream(conn net.Conn) (proxy.ProxyTarget, *acceptError) {
	if h.Protocol == ProtocolSOCKS5 {
		target, err := proxy.AcceptSOCKS5(conn, h.SocksCredentials)
		if err != nil {
			// AcceptSOCKS5 already wrote a SOCKS5 error reply where defined.
			return proxy.ProxyTarget{}, &acceptError{err: err, responded: true}
		}
		return target, nil
	}
	req, err := readCONNECT(conn)
	if err != nil {
		return proxy.ProxyTarget{}, &acceptError{err: err}
	}
	if req.method != "CONNECT" {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
		return proxy.ProxyTarget{}, &acceptError{
			err:       fmt.Errorf("method %q not allowed: only CONNECT is supported", req.method),
			responded: true,
		}
	}
	target, err := proxy.ParseTarget(req.target)
	if err != nil {
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
		return proxy.ProxyTarget{}, &acceptError{err: err, responded: true}
	}
	return target, nil
}

// denyDownstream reports a policy rejection to the downstream client.
func (h *Handler) denyDownstream(conn net.Conn) {
	if h.Protocol == ProtocolSOCKS5 {
		proxy.WriteSocks5Denied(conn)
		return
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
}

// failDownstream reports an upstream failure to the downstream client.
func (h *Handler) failDownstream(conn net.Conn) {
	if h.Protocol == ProtocolSOCKS5 {
		proxy.WriteSocks5Unreachable(conn)
		return
	}
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
}

// acceptedDownstream reports handshake success to the downstream client.
func (h *Handler) acceptedDownstream(conn net.Conn) error {
	if h.Protocol == ProtocolSOCKS5 {
		return proxy.WriteSocks5Success(conn)
	}
	_, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}

func (h *Handler) finish(conn net.Conn, ws *wsclient.Conn, s SessionStats, start time.Time, t2w, w2t int64) {
	s.Duration = time.Since(start)
	s.BytesTCPToWS = t2w
	s.BytesWSToTCP = w2t
	_ = conn.Close()
	if ws != nil {
		_ = ws.Close()
	}
	if h.OnFinish != nil {
		h.OnFinish(s)
	}
}

// PumpConfig tunes the bidirectional byte pump.
type PumpConfig struct {
	FrameSize   int
	IdleTimeout time.Duration // 0 = disabled
	MaxSession  time.Duration // 0 = unlimited
}

// Bridge pumps bytes both directions concurrently until both sides terminate.
// It returns (bytesTCPToWS, bytesWSToTCP, terminationReason).
// Backpressure is natural: both loops use synchronous blocking I/O with
// bounded buffers; there are no unbounded queues or channels.
func Bridge(ctx context.Context, tcp net.Conn, ws *wsclient.Conn, cfg PumpConfig) (int64, int64, string) {
	frameSize := cfg.FrameSize
	if frameSize <= 0 {
		frameSize = 16384
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var t2w, w2t atomic.Int64
	var lastActive atomic.Int64
	lastActive.Store(time.Now().UnixNano())
	touch := func() { lastActive.Store(time.Now().UnixNano()) }

	var wg sync.WaitGroup
	wg.Add(2)

	// Unblock transport I/O promptly on cancellation (shutdown, watchdog,
	// or peer exit). finish() closes the connections again; errors ignored.
	go func() {
		<-ctx.Done()
		_ = tcp.Close()
		_ = ws.Close()
	}()

	// wsClosed signals the TCP->WS loop to stop when the WS->TCP loop ends
	// (peer closed). Both directions then wind down; pending data already
	// written is preserved because each write completes before exit.
	reasonCh := make(chan string, 3)

	// Idle / max-session watchdog. Never injects bytes into the stream;
	// on expiry it closes both transports (unblocking the pump loops)
	// and cancels the pump.
	if cfg.IdleTimeout > 0 || cfg.MaxSession > 0 {
		deadline := time.Time{}
		if cfg.MaxSession > 0 {
			deadline = time.Now().Add(cfg.MaxSession)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := 1 * time.Second
			if cfg.IdleTimeout > 0 && cfg.IdleTimeout/2 < tick {
				tick = cfg.IdleTimeout / 2
			}
			t := time.NewTicker(tick)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case now := <-t.C:
					var reason string
					if !deadline.IsZero() && !now.Before(deadline) {
						reason = "max_session_duration"
					} else if cfg.IdleTimeout > 0 && now.Sub(time.Unix(0, lastActive.Load())) > cfg.IdleTimeout {
						reason = "idle_timeout"
					}
					if reason != "" {
						reasonCh <- reason
						_ = tcp.Close()
						_ = ws.Close()
						cancel()
						return
					}
				}
			}
		}()
	}

	// Direction 1: TCP -> WebSocket (binary messages, bounded frames).
	go func() {
		defer wg.Done()
		defer cancel()
		buf := make([]byte, frameSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_ = tcp.SetReadDeadline(time.Now().Add(5 * time.Minute))
			n, err := tcp.Read(buf)
			if n > 0 {
				// Copy because buf is reused across iterations.
				chunk := append([]byte(nil), buf[:n]...)
				if werr := ws.WriteChunks(chunk, frameSize); werr != nil {
					reasonCh <- "ws_write_failed"
					return
				}
				t2w.Add(int64(n))
				touch()
			}
			if err != nil {
				if errors.Is(err, io.EOF) || isTimeout(err) && n == 0 {
					// TCP half-close (EOF): orderly shutdown of the WS write
					// side; allow opposite direction to drain via cancel path.
					_ = ws.WriteControl(websocket.CloseMessage,
						websocket.FormatCloseMessage(websocket.CloseNoStatusReceived, ""),
						time.Now().Add(5*time.Second))
					reasonCh <- "tcp_eof"
				} else if n == 0 && err != nil {
					if isTimeout(err) {
						continue
					}
					reasonCh <- "tcp_read_failed"
				} else if err != nil {
					reasonCh <- "tcp_read_failed"
				}
				return
			}
		}
	}()

	// Direction 2: WebSocket -> TCP.
	go func() {
		defer wg.Done()
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			mt, msg, err := ws.ReadMessage()
			if err != nil {
				if websocket.IsCloseError(err,
					websocket.CloseNormalClosure,
					websocket.CloseGoingAway,
					websocket.CloseNoStatusReceived) || isWSClosed(err) {
					reasonCh <- "ws_closed"
				} else {
					reasonCh <- "ws_read_failed"
				}
				// Half-close: shutdown TCP write side so the server sees EOF
				// while we still allow TCP->WS to flush. Best effort.
				if tc, ok := tcp.(*net.TCPConn); ok {
					_ = tc.CloseWrite()
				}
				return
			}
			if mt != websocket.BinaryMessage {
				// Ignore non-binary frames (text/ping handled by library);
				// never inject control data into the opaque byte stream.
				continue
			}
			if len(msg) == 0 {
				continue
			}
			if _, err := writeFull(tcp, msg); err != nil {
				reasonCh <- "tcp_write_failed"
				return
			}
			w2t.Add(int64(len(msg)))
			touch()
		}
	}()

	wg.Wait()
	close(reasonCh)
	reason := "ok"
	for r := range reasonCh {
		// Prefer the first terminal reason; collapse tcp_eof+ws_closed to ok.
		if reason == "ok" {
			reason = r
		}
	}
	if reason == "tcp_eof" || reason == "ws_closed" {
		reason = "ok"
	}
	return t2w.Load(), w2t.Load(), reason
}

func writeFull(conn net.Conn, p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		n, err := conn.Write(p)
		total += n
		if err != nil {
			return total, err
		}
		p = p[n:]
	}
	return total, nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isWSClosed(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}

func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		return s[:120]
	}
	return s
}
