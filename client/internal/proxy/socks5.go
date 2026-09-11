package proxy

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// SOCKS5 protocol constants (RFC 1928). Only CONNECT is implemented;
// BIND and UDP ASSOCIATE are rejected.
const (
	socks5Version byte = 0x05

	socks5AuthNone     byte = 0x00
	socks5AuthPassword byte = 0x02
	socks5AuthNoAccept byte = 0xFF

	socks5CmdConnect byte = 0x01

	socks5AtypIPv4   byte = 0x01
	socks5AtypDomain byte = 0x03
	socks5AtypIPv6   byte = 0x04

	socks5RepSucceeded        byte = 0x00
	socks5RepNotAllowed       byte = 0x02
	socks5RepHostUnreachable  byte = 0x04
	socks5RepCmdNotSupported  byte = 0x07
	socks5RepAtypNotSupported byte = 0x08
)

// Socks5Credentials carries optional username/password authentication.
type Socks5Credentials struct {
	// Mode is "none" or "password".
	Mode     string
	Username string
	Password string
}

// AcceptSOCKS5 performs the SOCKS5 handshake (greeting + optional auth +
// CONNECT request) on conn and returns the requested target. On failure it
// writes the appropriate SOCKS5 error reply and returns an error.
// The caller sets deadlines; after success the connection carries the raw
// byte stream.
func AcceptSOCKS5(conn net.Conn, creds Socks5Credentials) (ProxyTarget, error) {
	if err := socks5Greet(conn, creds); err != nil {
		return ProxyTarget{}, err
	}
	target, cmdErr := socks5Request(conn)
	if cmdErr != nil {
		return ProxyTarget{}, cmdErr
	}
	return target, nil
}

func socks5Greet(conn net.Conn, creds Socks5Credentials) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5: read greeting: %w", err)
	}
	if hdr[0] != socks5Version {
		return fmt.Errorf("socks5: unsupported version %d", hdr[0])
	}
	nmethods := int(hdr[1])
	if nmethods == 0 || nmethods > 255 {
		return fmt.Errorf("socks5: invalid method count %d", nmethods)
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("socks5: read methods: %w", err)
	}

	wantPassword := creds.Mode == "password"
	var selected byte = socks5AuthNoAccept
	for _, m := range methods {
		if m == socks5AuthNone && !wantPassword {
			selected = socks5AuthNone
			break
		}
		if m == socks5AuthPassword && wantPassword {
			selected = socks5AuthPassword
			break
		}
	}
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return fmt.Errorf("socks5: write method selection: %w", err)
	}
	if selected == socks5AuthNoAccept {
		return fmt.Errorf("socks5: no acceptable auth method")
	}
	if selected == socks5AuthPassword {
		if err := socks5PasswordAuth(conn, creds); err != nil {
			return err
		}
	}
	return nil
}

func socks5PasswordAuth(conn net.Conn, creds Socks5Credentials) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("socks5: read auth header: %w", err)
	}
	if hdr[0] != 0x01 {
		return fmt.Errorf("socks5: unsupported auth version %d", hdr[0])
	}
	ulen := int(hdr[1])
	if ulen == 0 || ulen > 255 {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks5: invalid username length")
	}
	ubuf := make([]byte, ulen)
	if _, err := io.ReadFull(conn, ubuf); err != nil {
		return fmt.Errorf("socks5: read username: %w", err)
	}
	var plenBuf [1]byte
	if _, err := io.ReadFull(conn, plenBuf[:]); err != nil {
		return fmt.Errorf("socks5: read password length: %w", err)
	}
	plen := int(plenBuf[0])
	pbuf := make([]byte, plen)
	if _, err := io.ReadFull(conn, pbuf); err != nil {
		return fmt.Errorf("socks5: read password: %w", err)
	}
	if string(ubuf) != creds.Username || string(pbuf) != creds.Password {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks5: authentication failed")
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return fmt.Errorf("socks5: write auth response: %w", err)
	}
	return nil
}

func socks5Request(conn net.Conn) (ProxyTarget, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return ProxyTarget{}, fmt.Errorf("socks5: read request: %w", err)
	}
	if hdr[0] != socks5Version {
		return ProxyTarget{}, fmt.Errorf("socks5: unsupported version %d", hdr[0])
	}
	if hdr[1] != socks5CmdConnect {
		_ = socks5Reply(conn, socks5RepCmdNotSupported)
		return ProxyTarget{}, fmt.Errorf("socks5: command 0x%02x not supported (CONNECT only)", hdr[1])
	}
	var host string
	switch hdr[3] {
	case socks5AtypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return ProxyTarget{}, fmt.Errorf("socks5: read ipv4: %w", err)
		}
		host = net.IP(buf).String()
	case socks5AtypDomain:
		var lenBuf [1]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			return ProxyTarget{}, fmt.Errorf("socks5: read domain length: %w", err)
		}
		dlen := int(lenBuf[0])
		if dlen == 0 {
			_ = socks5Reply(conn, socks5RepHostUnreachable)
			return ProxyTarget{}, fmt.Errorf("socks5: empty domain")
		}
		dbuf := make([]byte, dlen)
		if _, err := io.ReadFull(conn, dbuf); err != nil {
			return ProxyTarget{}, fmt.Errorf("socks5: read domain: %w", err)
		}
		host = string(dbuf)
	case socks5AtypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return ProxyTarget{}, fmt.Errorf("socks5: read ipv6: %w", err)
		}
		host = net.IP(buf).String()
	default:
		_ = socks5Reply(conn, socks5RepAtypNotSupported)
		return ProxyTarget{}, fmt.Errorf("socks5: address type 0x%02x not supported", hdr[3])
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return ProxyTarget{}, fmt.Errorf("socks5: read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf[:])
	if port == 0 {
		_ = socks5Reply(conn, socks5RepHostUnreachable)
		return ProxyTarget{}, fmt.Errorf("socks5: invalid port 0")
	}
	target := ProxyTarget{Host: host, Port: port}
	if len(target.Host) > 253 {
		_ = socks5Reply(conn, socks5RepHostUnreachable)
		return ProxyTarget{}, fmt.Errorf("socks5: host too long")
	}
	return target, nil
}

// WriteSocks5Success writes the CONNECT success reply (bound address
// 0.0.0.0:0 — the local relay does not expose its own address).
func WriteSocks5Success(conn net.Conn) error {
	_, err := conn.Write([]byte{socks5Version, socks5RepSucceeded, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// WriteSocks5Denied writes a generic "connection not allowed" reply.
// Used when local policy rejects the target before any upstream dial.
func WriteSocks5Denied(conn net.Conn) {
	_ = socks5Reply(conn, socks5RepNotAllowed)
}

// WriteSocks5Unreachable writes a "host unreachable" reply.
// Used when the upstream (Worker/TCP) dial fails.
func WriteSocks5Unreachable(conn net.Conn) {
	_ = socks5Reply(conn, socks5RepHostUnreachable)
}

func socks5Reply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}
