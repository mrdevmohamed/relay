# Generic TCP Proxy over WebSocket (Go + Cloudflare Worker)

Any TCP application talks HTTP CONNECT or SOCKS5 to the local Go relay.
The relay forwards the opaque byte stream over WSS to a Cloudflare Worker,
which bridges it to the requested target host:port. Payloads are never
parsed, decrypted, inspected, or modified.

OpenVPN is one supported client among many — the proxy never knows or cares
what protocol flows through it.

## Architecture

```
Application
    |
    | HTTP CONNECT (127.0.0.1:8080) or SOCKS5 (127.0.0.1:1080)
    v
Local Go Relay
    |
    | WSS + {"type":"connect","host":..,"port":..} control handshake
    v
Cloudflare Worker (/connect)
    |
    | TCP socket (cloudflare:sockets)
    v
Target Host:Port
```

There is **no remote Go relay server**. The Cloudflare Worker itself is the
remote relay.

## How It Works

1. The app dials the local relay (`CONNECT example.com:443 HTTP/1.1`, or a
   SOCKS5 CONNECT for `example.com:443`). Both front ends produce the same
   internal `ProxyTarget{Host, Port}`.
2. The relay checks the target against its local `security:` policy, dials
   the single configured WSS endpoint with
   `Authorization: Bearer <RELAY_TOKEN>`, sends the JSON connect request,
   and waits for `{"type":"connected"}`. Only then does it answer the app
   (`200 Connection Established` / SOCKS5 success) and pump raw bytes both
   ways: TCP reads → WebSocket binary messages, WebSocket binary messages
   → TCP writes. Order is preserved; message boundaries are not significant.
3. The Worker validates the bearer token, returns `101`, reads the JSON
   connect request, re-validates the destination against its own policy
   (loopback/private/link-local/metadata blocked by default), opens an
   outbound TCP socket with `import { connect } from "cloudflare:sockets"`,
   replies `{"type":"connected"}`, and bridges WebSocket ↔ TCP concurrently
   until either side closes.

## Generic Application Examples

HTTP CONNECT proxy:

```bash
curl --proxy http://127.0.0.1:8080 https://example.com -v
```

SOCKS5 proxy (with remote DNS via `socks5h`):

```bash
curl --proxy socks5h://127.0.0.1:1080 https://example.com -v
```

With username/password (when `socks5.auth.mode: password`):

```bash
curl --proxy socks5h://user:pass@127.0.0.1:1080 https://example.com -v
```

Any application with native HTTP CONNECT or SOCKS5 support (browsers, git,
ssh via `nc -X`, package managers) works the same way.

## OpenVPN Use Case

```ini
client
dev tun
proto tcp-client
remote public-vpn-236.opengw.net 443
http-proxy 127.0.0.1 8080
http-proxy-retry
```

A ready profile is bundled:
`vpngate_public-vpn-236.opengw.net_tcp_443.via-relay.ovpn`
(same as the original `.ovpn`, plus the two `http-proxy` lines).
The proxy stays unaware that the bytes are OpenVPN.

## Local Relay Configuration

Copy and edit the example:

```bash
cp client/configs/client.example.yaml client/configs/client.yaml
export RELAY_TOKEN="your-secret-token"
./bin/relay-client --config ./client/configs/client.yaml
```

Key fields (`client/configs/client.example.yaml`):

```yaml
listen:
  http: "127.0.0.1:8080"    # "" disables; at least one must stay enabled
  socks5: "127.0.0.1:1080"

websocket:
  url: "wss://proxy.example.com/connect"
  token: "${RELAY_TOKEN}"

relay:
  frame_size: 16384
  connect_timeout: 10s
  idle_timeout: 10m          # idle sessions are closed
  max_session_duration: 0s   # 0 = unlimited
  ping_interval: 30s
  max_connections: 100

socks5:
  auth:
    mode: "none"             # or "password"
    username: ""
    password: ""

security:                    # local fast-path; Worker always re-validates
  allow_private_networks: false
  allow_loopback: false
  allow_link_local: false
  allowed_domains: []
  blocked_domains: []
  allowed_ports: []
```

- `frame_size` (default 16 KiB) bounds each WebSocket binary message; large
  TCP reads are split, small reads are sent as-is. Stream order is preserved.
- Domain targets are resolved locally and every resolved address is checked
  (DNS-rebinding protection); if local resolution itself fails, the request
  is allowed through and the Worker decides. The Worker re-checks literals and names.
- `ws://` URLs are only accepted for loopback test servers; production must
  use `wss://`.

CLI:

```bash
relay-client --config ./configs/client.yaml
relay-client --check-config ./configs/client.yaml
relay-client --version
```

## Cloudflare Worker Configuration

`worker/wrangler.jsonc` holds non-secret config under `vars`
(`ALLOW_*` / `ALLOWED_*` / `BLOCKED_*` policy, `MAX_CONNECTIONS`,
`MAX_MESSAGE_SIZE`). The secret is set separately and never committed:

```bash
cd worker
npm install
wrangler secret put RELAY_TOKEN
npm run deploy
```

Endpoint: `GET /connect` (sub-paths such as `/connect/eu`, `/connect/us`
are accepted and behave identically). Unknown paths return `404`. The
destination always comes from the JSON control message and is validated —
there are no server-side fixed routes and no `?host=`/`?port=` parameters.

Control protocol (`worker/src/protocol.ts`):

```
client -> {"type":"connect","host":"example.com","port":443}
worker -> {"type":"connected"}            # then binary relaying begins
worker -> {"type":"error","code":"blocked_destination|bad_request|tcp_failed","message":"..."}
```

## Authentication

- Local relay sends `Authorization: Bearer ${RELAY_TOKEN}` on the WSS upgrade.
- Worker compares against the `RELAY_TOKEN` secret with a timing-safe compare.
- Missing/invalid token → `401`. The token is never logged or reflected in
  errors.

## Deployment

### Worker (Wrangler)

1. `npm install -g wrangler` (or use the repo-local `npx wrangler`).
2. `wrangler login` to authenticate with Cloudflare.
3. `wrangler deploy --dry-run` to validate (or `npm run typecheck`).
4. Point your domain at the Worker (custom domain
   `proxy.example.com`, or `workers.dev` for testing).
5. `wrangler secret put RELAY_TOKEN`.
6. `npm run deploy`.
7. Verify auth is enforced (HTTP/1.1 required for the Upgrade header):
   `curl --http1.1 -s -o /dev/null -w "%{http_code}\n" -H "Upgrade: websocket" -H "Connection: Upgrade" https://proxy.example.com/connect`
   should return `401` without a token.

No `cloudflared` tunnel is required.

### Local relay (binary)

```bash
make build
export RELAY_TOKEN="..."
./bin/relay-client --config ./client/configs/client.yaml
```

### Docker

```bash
export RELAY_TOKEN="..."
docker compose up --build
```

`network_mode: host` is used so host-side apps can dial `127.0.0.1:8080`
(HTTP) and `127.0.0.1:1080` (SOCKS5). Ports `8080/1080/9090` are exposed.
The Worker is deployed with Wrangler, never containerized.

### systemd

```bash
sudo useradd -r -s /usr/sbin/nologin openvpn-relay
sudo install -m 0755 bin/relay-client /usr/local/bin/relay-client
sudo mkdir -p /etc/openvpn-ws-relay
sudo install -m 0600 client/configs/client.yaml /etc/openvpn-ws-relay/client.yaml
sudo install -m 0644 deploy/systemd/openvpn-ws-relay-client.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now openvpn-ws-relay-client
```

The unit sets `Restart=always`, `RestartSec=3`, `NoNewPrivileges=true`,
`PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=true`, and runs as
the dedicated non-root user.

## Local Testing

```bash
make test          # go test ./...
make test-race     # go test -race ./...
make lint          # go vet + gofmt check
cd worker && npm install && npm run typecheck && npm test
```

## End-to-End Testing

`client/internal/relay/relay_test.go` builds the full local topology in
process (the test bridge speaks the same JSON control handshake):

```
Fake TCP client -> Handler(HTTP CONNECT or SOCKS5) -> test WS bridge -> fake TCP echo server
```

It sends fragmented and large (4 MiB) random binary payloads over HTTP
CONNECT and 256 KiB over SOCKS5, asserting `input == output` exactly, plus
half-close, auth-failure (`502`), invalid method (`405`)/target (`400`),
policy rejection (`403`), frame-splitting (1 KiB frames carrying 64 KiB),
connection limits, idle timeout, and slow-consumer backpressure. The Worker
`test/relay.test.ts` asserts binary integrity for 256 KiB fragmented
payloads, text-frame isolation, and close handling; `security.test.ts` and
`protocol.test.ts` cover policy and the control handshake.

## Monitoring

- Go relay management (loopback only, default `127.0.0.1:9090`):
  - `GET /health` → `{"status":"ok",...}`
  - `GET /metrics` → Prometheus text (`active_connections`,
    `total_connections`, `failed_connections`, `bytes_tcp_to_ws`,
    `bytes_ws_to_tcp`, `connection_duration_seconds`).
- Structured `log/slog` lines (JSON by default) carry `connection_id`,
  `listener`, `protocol`, `client_address`, `target`, durations, byte counts,
  and `termination_reason`. Payload bytes, tokens, and credentials are never
  logged. The Worker logs the same metadata via `console.log` JSON.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `403 Forbidden` right after `CONNECT` | Local `security:` policy rejected the target (private/loopback/blocked) |
| SOCKS5 reply `0x02` | Same: local policy rejection |
| `502 Bad Gateway` / SOCKS5 `0x04` | WSS dial/auth/handshake failed, or Worker rejected the target (`blocked_destination`) / TCP dial failed |
| Worker `401` | missing/wrong `Authorization: Bearer` |
| Worker `404` | wrong path; must be `/connect` or `/connect/...` |
| Worker `426` | client did not send `Upgrade: websocket` (note: test with `--http1.1`) |
| Worker `503` | per-isolate connection limit reached; retry or raise `MAX_CONNECTIONS` |
| Session ends with `idle_timeout` | no bytes for `relay.idle_timeout`; raise it for quiet long-lived tunnels |
| Slow throughput | `frame_size` too small (more messages) or too large (head-of-line); 16 KiB default is a good start; check `tcp_nodelay` |

## Performance

- Streaming I/O with bounded buffers; no unbounded queues or session-sized
  allocations.
- `frame_size: 16384` splits large reads; tune per link (higher for stable
  high-bandwidth, lower for lossy links).
- `TCP_NODELAY` and keepalive configurable; WebSocket keepalive uses control
  ping frames (never in-band data).
- Backpressure is natural: each direction blocks on the slower side.

## Security

- WSS only in production; `ws://` refused except for loopback tests.
- Bearer-token auth on every upgrade; constant-time compare; no secret logging.
- Destinations validated on both ends: Go `security:` policy (with DNS
  resolution of every address) locally, Worker policy (literals, names,
  ports, domain lists) remotely. Default-deny for loopback, RFC1918,
  link-local (incl. `169.254.169.254` metadata), multicast, broadcast,
  `localhost`, and metadata hostnames. Port 25 blocked. No open proxy.
- Connection limits on both ends (`503` when saturated); bounded header
  parsing (8 KiB cap) and bounded message sizes (`MAX_MESSAGE_SIZE`).
- Idle and max-session timeouts bound resource use.
- Management endpoints bind loopback only; relay runs as non-root
  (Docker `nonroot`, systemd `openvpn-relay` + hardening flags).
- No payload logging anywhere.

## Migration Notes (from the OpenVPN-specific design)

What changed and why: the relay no longer proxies one fixed destination per
local port. Each connection carries its own target, so one HTTP port and one
SOCKS5 port serve every destination, with the Worker enforcing policy.

- Retained: Go app shape (`cmd/relay-client`, `internal/{proxy,websocket,
  relay,metrics,logging}`), `Bridge` streaming core, WS ping/pong, TCP
  keepalive/nodelay, metrics/health endpoints, Bearer auth, Dockerfile shape,
  systemd hardening, compose host-mode, Makefile targets, `.ovpn` profiles.
- Changed: config schema (`listeners[]` with `websocket_url`/`token`/
  `expected_destination` → `listen` + single `websocket` + `relay` +
  `socks5` + `security`); Worker endpoint (`/openvpn/<route>` →
  `/connect`); destination selection (fixed route table → per-connection
  control message + policy); session stats gained `protocol`/`target_*`.
- Removed: `worker/src/router.ts` (+ `router.test.ts`) fixed route table and
  `ROUTE_*` vars; `proxy.ValidateCONNECT` single-destination allowlist;
  `client/configs/vpngate.example.yaml` (fixed-route example; the generic
  `client.example.yaml` plus the `.via-relay.ovpn` cover it).
- Breaking: old `client.yaml` files and old `/openvpn/*` Worker URLs stop
  working. Migrate by copying the new `client.example.yaml`, pointing
  `websocket.url` at `.../connect`, setting `RELAY_TOKEN`, and redeploying
  the Worker (`npm run deploy` + `wrangler secret put RELAY_TOKEN` — the
  secret name is unchanged).
