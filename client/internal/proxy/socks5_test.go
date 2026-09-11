package proxy

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// socks5Client performs a minimal client handshake against the server side
// of conn and returns the server's reply bytes plus the negotiated target.
func socks5Client(t *testing.T, client net.Conn, user, pass string, atyp byte, addr []byte, port uint16) []byte {
	t.Helper()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	var greeting []byte
	if user == "" {
		greeting = []byte{0x05, 0x01, 0x00}
	} else {
		greeting = []byte{0x05, 0x02, 0x00, 0x02}
	}
	if _, err := client.Write(greeting); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	sel := make([]byte, 2)
	if _, err := readFull(client, sel); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if sel[0] != 0x05 {
		t.Fatalf("bad socks version %d", sel[0])
	}
	if user != "" {
		if sel[1] != 0x02 {
			t.Fatalf("expected password method, got 0x%02x", sel[1])
		}
		auth := []byte{0x01, byte(len(user))}
		auth = append(auth, []byte(user)...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, []byte(pass)...)
		if _, err := client.Write(auth); err != nil {
			t.Fatalf("write auth: %v", err)
		}
		resp := make([]byte, 2)
		if _, err := readFull(client, resp); err != nil {
			t.Fatalf("read auth response: %v", err)
		}
		if resp[1] != 0x00 {
			t.Fatalf("auth rejected: %v", resp)
		}
	} else if sel[1] != 0x00 {
		t.Fatalf("expected no-auth, got 0x%02x", sel[1])
	}
	req := []byte{0x05, 0x01, 0x00, atyp}
	req = append(req, addr...)
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], port)
	req = append(req, pb[:]...)
	if _, err := client.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := readFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return reply
}

func readFull(c net.Conn, b []byte) (int, error) {
	total := 0
	for total < len(b) {
		n, err := c.Read(b[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func TestSocks5IPv4NoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	type result struct {
		tgt ProxyTarget
		err error
	}
	done := make(chan result, 1)
	go func() {
		tgt, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		if err == nil {
			_ = WriteSocks5Success(server)
		}
		done <- result{tgt, err}
		_ = server.Close()
	}()
	reply := socks5Client(t, client, "", "", 0x01, []byte{93, 184, 216, 34}, 443)
	if reply[1] != 0x00 {
		t.Fatalf("expected success reply, got %v", reply)
	}
	// Server hasn't sent success yet (that is the relay's job); just verify
	// the handshake completed and reply shape is valid.
	r := <-done
	if r.err != nil {
		t.Fatalf("AcceptSOCKS5: %v", r.err)
	}
	if r.tgt.Host != "93.184.216.34" || r.tgt.Port != 443 {
		t.Fatalf("unexpected target: %+v", r.tgt)
	}
}

func TestSocks5DomainNoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	var got ProxyTarget
	go func() {
		tgt, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		if err == nil {
			_ = WriteSocks5Success(server)
		}
		got = tgt
		done <- err
		_ = server.Close()
	}()
	name := "example.com"
	addr := append([]byte{byte(len(name))}, []byte(name)...)
	_ = socks5Client(t, client, "", "", 0x03, addr, 8443)
	if err := <-done; err != nil {
		t.Fatalf("AcceptSOCKS5: %v", err)
	}
	if got.Host != "example.com" || got.Port != 8443 {
		t.Fatalf("unexpected target: %+v", got)
	}
}

func TestSocks5IPv6NoAuth(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	var got ProxyTarget
	go func() {
		tgt, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		if err == nil {
			_ = WriteSocks5Success(server)
		}
		got = tgt
		done <- err
		_ = server.Close()
	}()
	_ = socks5Client(t, client, "", "", 0x04, net.ParseIP("2001:db8::1").To16(), 80)
	if err := <-done; err != nil {
		t.Fatalf("AcceptSOCKS5: %v", err)
	}
	if got.Host != "2001:db8::1" || got.Port != 80 {
		t.Fatalf("unexpected target: %+v", got)
	}
}

func TestSocks5PasswordAuth(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "password", Username: "u", Password: "p"})
		if err == nil {
			_ = WriteSocks5Success(server)
		}
		done <- err
		_ = server.Close()
	}()
	_ = socks5Client(t, client, "u", "p", 0x01, []byte{1, 2, 3, 4}, 22)
	if err := <-done; err != nil {
		t.Fatalf("AcceptSOCKS5: %v", err)
	}
}

func TestSocks5PasswordAuthRejected(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "password", Username: "u", Password: "p"})
		done <- err
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte{0x05, 0x01, 0x02})
	sel := make([]byte, 2)
	if _, err := readFull(client, sel); err != nil || sel[1] != 0x02 {
		t.Fatalf("method selection: %v %v", sel, err)
	}
	bad := []byte{0x01, 1, 'u', 1, 'x'}
	_, _ = client.Write(bad)
	resp := make([]byte, 2)
	if _, err := readFull(client, resp); err != nil || resp[1] != 0x01 {
		t.Fatalf("expected auth failure, got %v %v", resp, err)
	}
	if err := <-done; err == nil {
		t.Fatal("expected auth error")
	}
}

func TestSocks5InvalidCommand(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		done <- err
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	sel := make([]byte, 2)
	_, _ = readFull(client, sel)
	// BIND command must be rejected with 0x07. Only the 4-byte header is
	// sent: the server rejects before reading address bytes, and net.Pipe
	// is unbuffered (extra bytes would deadlock the test; real TCP
	// buffers them harmlessly).
	_, _ = client.Write([]byte{0x05, 0x02, 0x00, 0x01})
	reply := make([]byte, 10)
	if _, err := readFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x07 {
		t.Fatalf("expected 0x07 cmd-not-supported, got 0x%02x", reply[1])
	}
	if err := <-done; err == nil {
		t.Fatal("expected command error")
	}
}

func TestSocks5InvalidAtyp(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		done <- err
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte{0x05, 0x01, 0x00})
	sel := make([]byte, 2)
	_, _ = readFull(client, sel)
	// Unknown ATYP must be rejected with 0x08 (header only; see above).
	_, _ = client.Write([]byte{0x05, 0x01, 0x00, 0x09})
	reply := make([]byte, 10)
	if _, err := readFull(client, reply); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if reply[1] != 0x08 {
		t.Fatalf("expected 0x08 atyp-not-supported, got 0x%02x", reply[1])
	}
	if err := <-done; err == nil {
		t.Fatal("expected atyp error")
	}
}

func TestSocks5BadVersion(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		_, err := AcceptSOCKS5(server, Socks5Credentials{Mode: "none"})
		done <- err
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	_, _ = client.Write([]byte{0x04, 0x01, 0x00})
	if err := <-done; err == nil {
		t.Fatal("expected version error")
	}
}

func TestWriteSocks5Replies(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	go func() {
		_ = WriteSocks5Success(server)
		_ = server.Close()
	}()
	_ = client.SetDeadline(time.Now().Add(5 * time.Second))
	reply := make([]byte, 10)
	if _, err := readFull(client, reply); err != nil {
		t.Fatalf("read: %v", err)
	}
	expected := []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(reply, expected) {
		t.Fatalf("unexpected success reply: %v", reply)
	}
}
