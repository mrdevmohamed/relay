// Cloudflare Worker entrypoint: generic authenticated WebSocket -> TCP relay.
//
// Flow: WSS /connect -> (auth) -> WebSocketPair -> 101 -> read JSON connect
//       control message -> validate destination policy -> cloudflare:sockets
//       connect() -> "connected" -> bidirectional binary relay (ctx.waitUntil).
//
// Proxied bytes are opaque end to end: no parsing, no inspection,
// no modification, no payload logging.

import { isAuthorized } from "./auth";
import { errorMessage, connectedMessage, readConnectRequest, sendControl, SessionState } from "./protocol";
import { policyFromEnv, validateTarget, type WorkerSecurityEnv } from "./security";
import { bridgeWebSocketToTcp } from "./relay";
import { openTcpConnection } from "./tcp";

export interface WorkerEnv extends WorkerSecurityEnv {
  RELAY_TOKEN: string;
  MAX_CONNECTIONS?: string;
  MAX_MESSAGE_SIZE?: string;
}

// Best-effort in-isolate connection accounting. (Workers scale horizontally,
// so this is a per-isolate guard, not a global limiter. Document as such.)
let activeConnections = 0;

export function __resetActiveConnectionsForTest(): void {
  activeConnections = 0;
}

export function __setActiveConnectionsForTest(n: number): void {
  activeConnections = n;
}

function parsePositiveInt(v: string | undefined, fallback: number): number {
  const n = parseInt((v ?? "").trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function wantsWebSocket(request: Request): boolean {
  const upgrade = request.headers.get("Upgrade");
  return !!upgrade && upgrade.trim().toLowerCase() === "websocket";
}

/** The relay endpoint: exactly /connect or any sub-path (/connect/eu, ...). */
export function isConnectPath(pathname: string): boolean {
  const p = pathname.split("?")[0] as string;
  const clean = (p.split("#")[0] as string).toLowerCase();
  return clean === "/connect" || clean.startsWith("/connect/");
}

export default {
  async fetch(request: Request, env: WorkerEnv, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const connectionId = crypto.randomUUID().slice(0, 8);
    let state: SessionState = SessionState.CONNECTING;

    // 1. Method: only GET is valid for WebSocket upgrades.
    if (request.method !== "GET") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    // 2. Upgrade header required (before leaking path/auth existence).
    if (!wantsWebSocket(request)) {
      return new Response("Upgrade Required", { status: 426 });
    }

    // 3. Path must be the relay endpoint. Unknown paths -> 404.
    if (!isConnectPath(url.pathname)) {
      return new Response("Not Found", { status: 404 });
    }

    // 4. Authentication (constant-time compare, no token in logs/errors).
    if (!isAuthorized(request, env.RELAY_TOKEN ?? "")) {
      return new Response("Unauthorized", { status: 401 });
    }
    state = SessionState.AUTHENTICATED;

    // 5. Connection limit.
    const maxConnections = parsePositiveInt(env.MAX_CONNECTIONS, 100);
    if (activeConnections >= maxConnections) {
      return new Response("Service Unavailable", { status: 503 });
    }

    // 6-7. WebSocket pair. Use half-open mode so we can coordinate close
    // across both sides of the proxy independently.
    const pair = new WebSocketPair();
    const client = pair[0] as unknown as WebSocket;
    const server = pair[1] as unknown as WebSocket;
    (server as unknown as { accept(opts?: object): void }).accept({ allowHalfOpen: true });
    // Deliver binary frames as ArrayBuffer so the relay stays synchronous.
    try {
      (server as unknown as { binaryType: string }).binaryType = "arraybuffer";
    } catch {
      // ignore: older runtimes default to arraybuffer already
    }

    activeConnections += 1;
    const maxMessageSize = parsePositiveInt(env.MAX_MESSAGE_SIZE, 1024 * 1024);
    const policy = policyFromEnv(env);
    const start = Date.now();
    console.log(
      JSON.stringify({
        msg: "relay session start",
        connection_id: connectionId,
        path: url.pathname,
        active_connections: activeConnections,
      }),
    );

    ctx.waitUntil(
      (async () => {
        try {
          // 8. Read the JSON connect control message.
          state = SessionState.CONNECT_REQUESTED;
          let target;
          try {
            target = await readConnectRequest(server, 10_000);
          } catch {
            sendControl(server, errorMessage("bad_request", "invalid connect request"));
            try {
              server.close(1008, "bad request");
            } catch {
              // ignore
            }
            state = SessionState.CLOSED;
            return;
          }
          // 9. Validate destination policy.
          const verdict = validateTarget(target.host, target.port, policy);
          if (!verdict.ok) {
            sendControl(server, errorMessage("blocked_destination", "destination not allowed"));
            try {
              server.close(1008, "destination not allowed");
            } catch {
              // ignore
            }
            console.log(
              JSON.stringify({
                msg: "relay destination blocked",
                connection_id: connectionId,
                reason: verdict.reason,
                port: target.port,
              }),
            );
            state = SessionState.CLOSED;
            return;
          }
          // 10. Outbound TCP to the validated destination.
          let tcp;
          try {
            tcp = await openTcpConnection(verdict.host as string, verdict.port as number, 10_000);
          } catch {
            // Generic error: never expose hostname/port or dial details.
            sendControl(server, errorMessage("tcp_failed", "upstream unreachable"));
            try {
              server.close(1014, "upstream unreachable");
            } catch {
              // ignore
            }
            state = SessionState.CLOSED;
            return;
          }
          state = SessionState.CONNECTED;
          sendControl(server, connectedMessage());
          state = SessionState.RELAYING;
          const stats = await bridgeWebSocketToTcp(server, tcp, {
            maxMessageSize,
            connectionId,
          });
          state = SessionState.CLOSING;
          console.log(
            JSON.stringify({
              msg: "relay session closed",
              connection_id: connectionId,
              target: (verdict.host as string) + ":" + String(verdict.port),
              duration_ms: Date.now() - start,
              bytes_ws_to_tcp: stats.bytesWsToTcp,
              bytes_tcp_to_ws: stats.bytesTcpToWs,
              termination_reason: stats.reason,
            }),
          );
          state = SessionState.CLOSED;
        } catch (e) {
          console.log(
            JSON.stringify({
              msg: "relay session error",
              connection_id: connectionId,
              termination_reason: "bridge_failed",
            }),
          );
          void e;
          void state;
          state = SessionState.CLOSED;
        } finally {
          activeConnections = Math.max(0, activeConnections - 1);
        }
      })(),
    );

    return new Response(null, { status: 101, webSocket: client });
  },
} satisfies ExportedHandler<WorkerEnv>;
