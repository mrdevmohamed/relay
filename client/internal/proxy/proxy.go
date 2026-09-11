package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/textproto"
	"strings"
)

// MaxHeaderBytes caps the CONNECT header block (prevents memory exhaustion).
const MaxHeaderBytes = 8192

// Request is a parsed HTTP CONNECT request. Only CONNECT is supported;
// the relay is not a general HTTP forward proxy.
type Request struct {
	Method    string
	Target    string // host:port as sent by the client
	Proto     string // e.g. HTTP/1.1
	Headers   map[string]string
	Host      string
	RawTarget string
}

// ParseCONNECT reads and parses a single HTTP request from br.
// It enforces CONNECT-only semantics and bounded header size.
func ParseCONNECT(br *bufio.Reader) (*Request, error) {
	// Bound the total buffered peek to avoid unbounded allocation.
	// bufio.Reader may grow; we enforce a line+header budget manually.
	tp := textproto.NewReader(br)

	line, err := tp.ReadLine()
	if err != nil {
		return nil, fmt.Errorf("read request line: %w", err)
	}
	if len(line) > 2048 {
		return nil, fmt.Errorf("request line too long")
	}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed request line")
	}
	method, target, proto := parts[0], strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])

	headers := map[string]string{}
	total := len(line)
	for {
		hline, err := tp.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("read header: %w", err)
		}
		total += len(hline)
		if total > MaxHeaderBytes {
			return nil, fmt.Errorf("headers too large")
		}
		if hline == "" {
			break // end of headers
		}
		if len(hline) > 2048 {
			return nil, fmt.Errorf("header line too long")
		}
		colon := strings.Index(hline, ":")
		if colon <= 0 {
			return nil, fmt.Errorf("malformed header line")
		}
		name := strings.ToLower(strings.TrimSpace(hline[:colon]))
		value := strings.TrimSpace(hline[colon+1:])
		// Keep first occurrence (Host etc.); concatenate duplicates minimally.
		if _, ok := headers[name]; !ok {
			headers[name] = value
		}
	}

	if !strings.HasPrefix(proto, "HTTP/") {
		return nil, fmt.Errorf("unsupported protocol %q", proto)
	}
	return &Request{
		Method:    method,
		Target:    target,
		Proto:     proto,
		Headers:   headers,
		Host:      headers["host"],
		RawTarget: target,
	}, nil
}

// ValidateCONNECT enforces CONNECT-only + allowlisted destination.
// expectedDestination is the single permitted "host:port" (case-insensitive
// host comparison). Empty expectedDestination always rejects (fail-closed:
// the relay must never become an open proxy).
func ValidateCONNECT(req *Request, expectedDestination string) error {
	if req.Method != "CONNECT" {
		return fmt.Errorf("method %q not allowed: only CONNECT is supported", req.Method)
	}
	if expectedDestination == "" {
		return fmt.Errorf("no expected destination configured: refusing to proxy")
	}
	if req.Target == "" {
		return fmt.Errorf("missing CONNECT target")
	}
	if !equalHostPort(req.Target, expectedDestination) {
		return fmt.Errorf("destination %q is not allowed", req.Target)
	}
	if _, _, err := net.SplitHostPort(req.Target); err != nil {
		return fmt.Errorf("invalid CONNECT target %q: %w", req.Target, err)
	}
	return nil
}

func equalHostPort(a, b string) bool {
	ha, pa, errA := net.SplitHostPort(strings.TrimSpace(a))
	hb, pb, errB := net.SplitHostPort(strings.TrimSpace(b))
	if errA != nil || errB != nil {
		// Fall back to exact (case-insensitive) comparison.
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return strings.EqualFold(ha, hb) && pa == pb
}

// WriteSuccess writes "HTTP/1.1 200 Connection Established\r\n\r\n".
func WriteSuccess(conn net.Conn) error {
	_, err := fmt.Fprintf(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	return err
}

// WriteError writes a minimal status line with no body and Connection: close.
func WriteError(conn net.Conn, statusCode int, reason string) {
	_, _ = fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nConnection: close\r\n\r\n", statusCode, reason)
}
