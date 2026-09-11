// WebSocket control protocol between the local relay and the Worker.
//
// Immediately after the WebSocket is established the client sends:
//
//   {"type":"connect","host":"example.com","port":443}
//
// The Worker validates the destination, dials TCP, then replies:
//
//   {"type":"connected"}
//
// Only then may binary payload frames begin. Failures are reported as:
//
//   {"type":"error","code":"blocked_destination|bad_request|tcp_failed","message":"..."}
//
// Normal proxy traffic is binary only — never JSON, never base64.

/** Lifecycle states of one relayed session. */
export const enum SessionState {
  CONNECTING = "CONNECTING",
  AUTHENTICATED = "AUTHENTICATED",
  CONNECT_REQUESTED = "CONNECT_REQUESTED",
  CONNECTED = "CONNECTED",
  RELAYING = "RELAYING",
  CLOSING = "CLOSING",
  CLOSED = "CLOSED",
}

export interface ConnectRequest {
  type: "connect";
  host: string;
  port: number;
}

export interface ConnectedResponse {
  type: "connected";
}

export type ErrorCode = "bad_request" | "blocked_destination" | "tcp_failed" | "timeout";

export interface ErrorResponse {
  type: "error";
  code: ErrorCode;
  message: string;
}

/** Parse and shape-validate a connect control message. Returns null when invalid. */
export function parseConnectRequest(data: unknown): ConnectRequest | null {
  if (typeof data !== "string") return null;
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(data) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (obj["type"] !== "connect") return null;
  if (typeof obj["host"] !== "string") return null;
  const host = (obj["host"] as string).trim();
  if (host.length === 0 || host.length > 253) return null;
  if (typeof obj["port"] !== "number" || !Number.isInteger(obj["port"])) return null;
  const port = obj["port"] as number;
  if (port < 1 || port > 65535) return null;
  return { type: "connect", host, port };
}

export function connectedMessage(): string {
  return JSON.stringify({ type: "connected" } satisfies ConnectedResponse);
}

export function errorMessage(code: ErrorCode, message: string): string {
  // Generic messages only; never include tokens, internal hosts, or dial details.
  return JSON.stringify({ type: "error", code, message } satisfies ErrorResponse);
}

interface EventedWebSocket {
  send(data: string | ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (event: { data?: unknown }) => void): void;
  removeEventListener?(type: string, listener: (event: { data?: unknown }) => void): void;
}

/**
 * Wait for the client's connect control message (a text frame).
 * Non-text frames received while waiting are ignored. Rejects on timeout
 * or when the socket closes first.
 */
export function readConnectRequest(ws: WebSocket | EventedWebSocket, timeoutMs = 10_000): Promise<ConnectRequest> {
  const socket = ws as EventedWebSocket;
  return new Promise<ConnectRequest>((resolve, reject) => {
    let done = false;
    const finish = (fn: () => void): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      detach();
      fn();
    };
    const timer = setTimeout(() => {
      finish(() => reject(new Error("timeout")));
    }, timeoutMs);
    // setTimeout keeps the isolate alive only via waitUntil in production;
    // unref where available (tests) so idle handles don't hang the process.
    const t = timer as unknown as { unref?: () => void };
    if (typeof t.unref === "function") t.unref();

    const onMessage = (event: { data?: unknown }): void => {
      const data = event.data;
      // Binary frames before the handshake are protocol violations; ignore
      // them rather than injecting them into any stream (no stream exists yet).
      if (typeof data !== "string") return;
      const req = parseConnectRequest(data);
      if (!req) {
        finish(() => reject(new Error("bad_request")));
        return;
      }
      finish(() => resolve(req));
    };
    const onClose = (): void => {
      finish(() => reject(new Error("closed")));
    };
    const detach = (): void => {
      try {
        socket.removeEventListener?.("message", onMessage);
        socket.removeEventListener?.("close", onClose);
      } catch {
        // ignore: not all runtimes implement removeEventListener
      }
    };
    socket.addEventListener("message", onMessage);
    socket.addEventListener("close", onClose);
    socket.addEventListener("error", onClose);
  });
}

/** Best-effort text send; never throws. */
export function sendControl(ws: WebSocket | EventedWebSocket, text: string): void {
  try {
    (ws as EventedWebSocket).send(text);
  } catch {
    // ignore: peer already gone
  }
}
