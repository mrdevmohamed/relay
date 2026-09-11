// Command relay-client is a generic local proxy (HTTP CONNECT + SOCKS5)
// that transports opaque TCP byte streams over WebSocket/WSS to a
// Cloudflare Worker, which bridges them to the requested target host:port.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/config"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/logging"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/metrics"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/relay"
	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/security"
	wsclient "github.com/example/openvpn-ws-cloudflare-relay/client/internal/websocket"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	var (
		configPath  string
		checkConfig bool
		showVersion bool
	)
	flag.StringVar(&configPath, "config", "./configs/client.yaml", "path to YAML config file")
	flag.BoolVar(&checkConfig, "check-config", false, "validate config and exit")
	flag.BoolVar(&showVersion, "version", false, "print version and exit")
	flag.Parse()

	// Allow: relay-client --check-config ./path (flag pkg handles `--check-config path` only
	// with `=`; also accept a positional arg as the config path when checking).
	if checkConfig && flag.NArg() > 0 && configPath == "./configs/client.yaml" {
		configPath = flag.Arg(0)
	}

	if showVersion {
		fmt.Printf("relay-client %s (built %s)\n", version, buildTime)
		os.Exit(0)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if checkConfig {
		fmt.Println("config OK")
		os.Exit(0)
	}

	logger := logging.Setup(cfg.Logging.Level, cfg.Logging.Format)
	httpAddr, socksAddr := derefOrEmpty(cfg.Listen.HTTP), derefOrEmpty(cfg.Listen.SOCKS5)
	logger.Info("relay-client starting", "version", version,
		"http", httpAddr, "socks5", socksAddr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	m := metrics.Default

	// Management interface (private loopback): /health and /metrics.
	mgmtSrv := &http.Server{
		Addr:              cfg.Management.Address,
		Handler:           metrics.Handler(m),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		logger.Info("management listening", "address", cfg.Management.Address)
		if err := mgmtSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("management server failed", "error", err)
		}
	}()

	// Shared session state across both front ends.
	var active atomic.Int64
	policy := security.Policy{
		AllowPrivateNetworks: cfg.Security.AllowPrivateNetworks,
		AllowLoopback:        cfg.Security.AllowLoopback,
		AllowLinkLocal:       cfg.Security.AllowLinkLocal,
		AllowedDomains:       cfg.Security.AllowedDomains,
		BlockedDomains:       cfg.Security.BlockedDomains,
		AllowedPorts:         cfg.Security.AllowedPorts,
	}
	newHandler := func(protocol, name string) *relay.Handler {
		return &relay.Handler{
			ListenerName:   name,
			Protocol:       protocol,
			Policy:         policy,
			FrameSize:      cfg.Relay.FrameSize,
			IdleTimeout:    time.Duration(cfg.Relay.IdleTimeout),
			MaxSession:     time.Duration(cfg.Relay.MaxSessionDuration),
			MaxConnections: cfg.Relay.MaxConnections,
			Active:         &active,
			Logger:         logger.With("listener", name, "protocol", protocol),
			SocksCredentials: proxy.Socks5Credentials{
				Mode:     strings.ToLower(cfg.Socks5.Auth.Mode),
				Username: cfg.Socks5.Auth.Username,
				Password: cfg.Socks5.Auth.Password,
			},
			Dial: func(dialCtx context.Context) (*wsclient.Conn, error) {
				d := &wsclient.Dialer{
					URL:            cfg.Websocket.URL,
					Token:          cfg.Websocket.Token,
					ConnectTimeout: time.Duration(cfg.Relay.ConnectTimeout),
					PingInterval:   time.Duration(cfg.Relay.PingInterval),
				}
				return d.Dial(dialCtx)
			},
			OnFinish: func(s relay.SessionStats) {
				m.BytesTCPToWS.Add(s.BytesTCPToWS)
				m.BytesWSToTCP.Add(s.BytesWSToTCP)
				m.ObserveDuration(s.Duration)
				if s.Reason != "ok" && s.Reason != "" {
					m.FailedConnections.Add(1)
				}
			},
		}
	}

	var wg sync.WaitGroup
	if httpAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serve(ctx, cfg, "http", httpAddr, newHandler(relay.ProtocolHTTP, "http"), m, logger); err != nil {
				logger.Error("listener exited", "protocol", "http", "address", httpAddr, "error", err)
			}
		}()
	}
	if socksAddr != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := serve(ctx, cfg, "socks5", socksAddr, newHandler(relay.ProtocolSOCKS5, "socks5"), m, logger); err != nil {
				logger.Error("listener exited", "protocol", "socks5", "address", socksAddr, "error", err)
			}
		}()
	}

	<-ctx.Done()
	logger.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = mgmtSrv.Shutdown(shutCtx)
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-shutCtx.Done():
	}
}

func serve(ctx context.Context, cfg *config.Config, protocol, addr string, h *relay.Handler, m *metrics.Metrics, logger *slog.Logger) error {
	lc := net.ListenConfig{
		KeepAlive: time.Duration(cfg.TCP.KeepAlive),
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer ln.Close()
	logger.Info("proxy listening", "protocol", protocol, "address", addr, "worker", redactHost(cfg.Websocket.URL))

	// Track totals at accept time.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
			}
			// Transient accept error backoff.
			logger.Warn("accept failed", "protocol", protocol, "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetKeepAlive(true)
			if d := time.Duration(cfg.TCP.KeepAlive); d > 0 {
				_ = tc.SetKeepAlivePeriod(d)
			}
			_ = tc.SetNoDelay(cfg.TCP.TCPNoDelay)
		}
		m.TotalConnections.Add(1)
		m.ActiveConnections.Add(1)
		go func(c net.Conn) {
			defer m.ActiveConnections.Add(-1)
			h.Serve(ctx, c)
		}(conn)
	}
}

func derefOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func redactHost(u string) string {
	// Strip any query; never log tokens.
	for i := range u {
		if u[i] == '?' {
			return u[:i]
		}
	}
	return u
}
