# Generic TCP-over-WebSocket Relay Worker

Cloudflare Worker that accepts an authenticated WebSocket on `GET /connect`
(and `/connect/*` aliases), reads a JSON `{"type":"connect","host","port"}`
control message, validates the destination against the security policy, and
bridges the socket to an outbound TCP destination via `cloudflare:sockets`.

Proxied bytes are opaque: the Worker never parses, inspects, or modifies
payload bytes. Payloads travel as binary frames only.

## Endpoint

`GET /connect` with `Upgrade: websocket` and
`Authorization: Bearer <RELAY_TOKEN>`.

Control protocol (see `src/protocol.ts`):

```
client -> {"type":"connect","host":"example.com","port":443}
worker -> {"type":"connected"}
worker -> {"type":"error","code":"...","message":"..."}  # on failure
```

## Security policy

Configured via `vars` in `wrangler.jsonc` (see `src/security.ts`):

| Var | Default | Meaning |
|-----|---------|---------|
| `ALLOW_PRIVATE_NETWORKS` | `false` | allow 10/8, 172.16/12, 192.168/16, fc00::/7 |
| `ALLOW_LOOPBACK` | `false` | allow 127/8, ::1, localhost |
| `ALLOW_LINK_LOCAL` | `false` | allow 169.254/16 (incl. metadata IP), fe80::/10 |
| `ALLOWED_DOMAINS` | `` | comma list; when set, names must match |
| `BLOCKED_DOMAINS` | `` | comma list; matches (incl. subdomains) rejected |
| `ALLOWED_PORTS` | `` | comma list; when set, only these ports |

Always blocked: port 0 and 25, multicast, broadcast, metadata hostnames.
Clients cannot supply destinations outside policy — there are no fixed
routes and no `?host=`/`?port=` parameters.

## Auth

Send `Authorization: Bearer <RELAY_TOKEN>` on the upgrade request.
`RELAY_TOKEN` is a Worker secret (`wrangler secret put RELAY_TOKEN`).

## Status codes

- `101` valid upgrade (WebSocket established)
- `401` missing/invalid token
- `404` unknown path
- `405` non-GET method
- `426` missing `Upgrade: websocket`
- `502` TCP dial failed (generic, no internals leaked)
- `503` connection limit reached

## Develop

```bash
npm install
npm run typecheck
npm test
npx wrangler dev
npm run deploy
```
