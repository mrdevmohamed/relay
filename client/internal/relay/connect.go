package relay

import (
	"bufio"
	"net"

	"github.com/example/openvpn-ws-cloudflare-relay/client/internal/proxy"
)

type connectRequest struct {
	method string
	target string
	proto  string
}

// readCONNECT parses one CONNECT request from conn. The caller sets deadlines.
func readCONNECT(conn net.Conn) (*connectRequest, error) {
	br := bufio.NewReader(conn)
	req, err := proxy.ParseCONNECT(br)
	if err != nil {
		return nil, err
	}
	return &connectRequest{method: req.Method, target: req.Target, proto: req.Proto}, nil
}
