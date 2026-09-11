// Bidirectional WebSocket <-> TCP bridge. Both directions run concurrently;
// payloads are opaque binary and are never inspected, parsed, or logged.
// NOTE: this module intentionally does NOT import "./tcp" at runtime so unit
// tests can run under plain node/vitest without the `cloudflare:sockets`
// runtime module. The TcpConnection shape mirrors tcp.ts structurally.

export interface TcpConnection {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed: Promise<void>;
  close: () => Promise<void>;
}

async function closeTcp(sock: TcpConnection | null): Promise<void> {
  if (!sock) return;
  try {
    await sock.close();
  } catch {
    // ignore
  }
}

export interface BridgeOptions {
  /** Max inbound WebSocket message size in bytes (default 1 MiB). */
  maxMessageSize?: number;
  /** Tag for log correlation only. */
  connectionId?: string;
}

export interface BridgeStats {
  bytesWsToTcp: number;
  bytesTcpToWs: number;
  reason: string;
}

interface MinimalWebSocket {
  accept(options?: { allowHalfOpen?: boolean }): void;
  send(data: ArrayBuffer | Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(type: string, listener: (event: { data?: unknown } & Record<string, unknown>) => void): void;
  readonly readyState: number;
}

function toUint8(data: unknown): Uint8Array | null {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  // With the default binaryType ("blob"), binary frames arrive as Blobs and
  // are handled by the caller via arrayBuffer(). Anything else (strings from
  // text frames) is control noise and must not enter the byte stream.
  return null;
}

/**
 * Bridge an accepted server WebSocket to an open TCP socket.
 * Resolves when both directions have terminated; always cleans up both sides.
 */
export async function bridgeWebSocketToTcp(
  ws: WebSocket | MinimalWebSocket,
  tcp: TcpConnection,
  opts: BridgeOptions = {},
): Promise<BridgeStats> {
  const maxMessageSize = opts.maxMessageSize ?? 1024 * 1024;
  const stats: BridgeStats = { bytesWsToTcp: 0, bytesTcpToWs: 0, reason: "ok" };

  const socket = ws as MinimalWebSocket;
  const writer = tcp.writable.getWriter();
  const tcpReader = tcp.readable.getReader();
  let wsToTcpDone = false;
  let tcpToWsDone = false;
  let wakeWs: (() => void) | null = null;

  // --- Direction 1: WebSocket -> TCP (event-driven queue) ---
  const wsToTcp = (async (): Promise<string> => {
    const queue: Array<Uint8Array> = [];
    let resolveWait: (() => void) | null = null;
    let wsClosed = false;
    let wsError: unknown = null;

    const wake = (): void => {
      if (resolveWait) {
        const r = resolveWait;
        resolveWait = null;
        r();
      }
    };
    wakeWs = wake;

    const onMessage = (event: { data?: unknown }): void => {
      const data = (event as { data?: unknown }).data;
      // Blob delivery (default binaryType) needs async extraction.
      if (typeof Blob !== "undefined" && data instanceof Blob) {
        void (data as Blob)
          .arrayBuffer()
          .then((ab) => {
            const u8 = new Uint8Array(ab);
            if (u8.byteLength > maxMessageSize) {
              wsError = new Error("message too large");
              wsClosed = true;
              wake();
              return;
            }
            if (u8.byteLength > 0) {
              queue.push(u8);
              wake();
            }
          })
          .catch((e: unknown) => {
            wsError = e;
            wsClosed = true;
            wake();
          });
        return;
      }
      const u8 = toUint8(data);
      if (!u8) return; // ignore text/control frames
      if (u8.byteLength > maxMessageSize) {
        wsError = new Error("message too large");
        wsClosed = true;
        wake();
        return;
      }
      if (u8.byteLength === 0) return;
      queue.push(u8);
      wake();
    };

    const onClose = (): void => {
      wsClosed = true;
      wake();
    };

    socket.addEventListener("message", onMessage as (e: { data?: unknown } & Record<string, unknown>) => void);
    socket.addEventListener("close", onClose as (e: { data?: unknown } & Record<string, unknown>) => void);
    socket.addEventListener("error", onClose as (e: { data?: unknown } & Record<string, unknown>) => void);

    try {
      for (;;) {
        while (queue.length === 0 && !wsClosed) {
          await new Promise<void>((resolve) => {
            resolveWait = resolve;
          });
        }
        while (queue.length > 0) {
          const chunk = queue.shift() as Uint8Array;
          try {
            await writer.write(chunk);
          } catch {
            return "tcp_write_failed";
          }
          stats.bytesWsToTcp += chunk.byteLength;
        }
        if (wsClosed) {
          if (wsError) return "ws_read_failed";
          return "ws_closed";
        }
      }
    } finally {
      wsToTcpDone = true;
      wakeWs = null;
      // Half-close: signal EOF to the TCP server while TCP->WS still drains.
      try {
        await writer.close();
      } catch {
        // ignore
      }
      // Unblock the TCP->WS read loop so the bridge can terminate when the
      // WebSocket side closes first. The pending reader.read() resolves done.
      // NOTE: must cancel via the active reader (stream is locked).
      try {
        await tcpReader.cancel();
      } catch {
        // ignore (already closed/cancelled in tests)
      }
      void tcpToWsDone;
    }
  })();

  // --- Direction 2: TCP -> WebSocket (streaming read loop) ---
  const tcpToWs = (async (): Promise<string> => {
    const reader = tcpReader;
    try {
      for (;;) {
        let result: ReadableStreamReadResult<Uint8Array>;
        try {
          result = await reader.read();
        } catch {
          return "tcp_read_failed";
        }
        if (result.done) return "tcp_eof";
        const chunk = result.value;
        if (!chunk || chunk.byteLength === 0) continue;
        try {
          // Copy to a fresh ArrayBuffer; send as binary.
          const copy = chunk.slice().buffer as ArrayBuffer;
          (socket as { send(d: ArrayBuffer): void }).send(copy);
        } catch {
          return "ws_write_failed";
        }
        stats.bytesTcpToWs += chunk.byteLength;
        if (wsToTcpDone) {
          // Peer is gone; keep draining briefly is handled by close below.
        }
      }
    } finally {
      try {
        reader.releaseLock();
      } catch {
        // ignore
      }
      tcpToWsDone = true;
      // Wake the WS->TCP loop if it is still waiting (TCP EOF first).
      try {
        const w = wakeWs as unknown as (() => void) | null;
        w?.();
      } catch {
        // ignore
      }
      void wsToTcpDone;
    }
  })();

  const [r1, r2] = await Promise.all([wsToTcp, tcpToWs]);

  // Cleanup: close both transports cleanly.
  try {
    writer.releaseLock();
  } catch {
    // ignore
  }
  await closeTcp(tcp);
  try {
    socket.close(1000, "done");
  } catch {
    // ignore
  }

  stats.reason = pickReason(r1, r2);
  return stats;
}

function pickReason(a: string, b: string): string {
  // Clean EOF-driven shutdown collapses to "ok".
  const clean = new Set(["ws_closed", "tcp_eof", "ok"]);
  if (clean.has(a) && clean.has(b)) return "ok";
  // Prefer the failure reason.
  if (!clean.has(a)) return a;
  if (!clean.has(b)) return b;
  return "ok";
}
