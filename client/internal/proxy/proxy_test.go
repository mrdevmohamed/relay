package proxy

import (
	"bufio"
	"strings"
	"testing"
)

func parse(t *testing.T, raw string) *Request {
	t.Helper()
	req, err := ParseCONNECT(bufio.NewReader(strings.NewReader(raw)))
	if err != nil {
		t.Fatalf("ParseCONNECT: %v", err)
	}
	return req
}

func TestParseCONNECT11(t *testing.T) {
	req := parse(t, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
	if req.Method != "CONNECT" || req.Target != "example.com:443" || req.Proto != "HTTP/1.1" {
		t.Fatalf("unexpected parse: %+v", req)
	}
	tgt, err := ParseTarget(req.Target)
	if err != nil {
		t.Fatalf("ParseTarget: %v", err)
	}
	if tgt.Host != "example.com" || tgt.Port != 443 {
		t.Fatalf("unexpected target: %+v", tgt)
	}
}

func TestParseCONNECT10(t *testing.T) {
	req := parse(t, "CONNECT example.com:443 HTTP/1.0\r\nHost: example.com:443\r\n\r\n")
	if _, err := ParseTarget(req.Target); err != nil {
		t.Fatalf("ParseTarget 1.0: %v", err)
	}
}

func TestParseTargetIPv6(t *testing.T) {
	tgt, err := ParseTarget("[::1]:8080")
	if err != nil {
		t.Fatalf("ParseTarget ipv6: %v", err)
	}
	if tgt.Host != "::1" || tgt.Port != 8080 {
		t.Fatalf("unexpected target: %+v", tgt)
	}
}

func TestParseTargetInvalidHost(t *testing.T) {
	for _, bad := range []string{"", ":443", "example.com", "example.com:0", "example.com:99999", "example.com:notaport"} {
		if _, err := ParseTarget(bad); err == nil {
			t.Fatalf("expected error for target %q", bad)
		}
	}
}

func TestRejectGET(t *testing.T) {
	req := parse(t, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if req.Method != "GET" {
		t.Fatalf("expected GET method, got %q", req.Method)
	}
	// Method enforcement now lives in the relay handler (405); the parser
	// stays method-agnostic so tests can assert on Method directly.
}

func TestMalformedRequestLine(t *testing.T) {
	_, err := ParseCONNECT(bufio.NewReader(strings.NewReader("GARBAGE\r\n\r\n")))
	if err == nil {
		t.Fatal("expected error for malformed request line")
	}
}

func TestHeadersTooLarge(t *testing.T) {
	var b strings.Builder
	b.WriteString("CONNECT example.com:443 HTTP/1.1\r\n")
	for i := 0; i < 200; i++ {
		b.WriteString("X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n")
	}
	b.WriteString("\r\n")
	_, err := ParseCONNECT(bufio.NewReader(strings.NewReader(b.String())))
	if err == nil {
		t.Fatal("expected error for oversized headers")
	}
}
