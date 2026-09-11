import { describe, expect, it, vi, beforeEach } from "vitest";
import { bridgeWebSocketToTcp } from "../src/relay";

// Minimal fakes: no network, pure in-memory streams.

function makeTcpPair() {
  // backendReadable: what the bridge reads from TCP (server -> client path).
  let backendController: ReadableStreamDefaultController<Uint8Array>;
  const backendReadable = new ReadableStream<Uint8Array>({
    start(c) {
      backendController = c;
    },
  });
  const written: Uint8Array[] = [];
  const writable = new WritableStream<Uint8Array>({
    write(chunk) {
      written.push(chunk.slice());
    },
  });
  const tcp = {
    readable: backendReadable,
    writable,
    opened: Promise.resolve({}),
    closed: Promise.resolve(),
    close: vi.fn(async () => {}),
  };
  return {
    tcp,
    written,
    pushFromBackend(chunk: Uint8Array) {
      backendController.enqueue(chunk);
    },
    closeBackend() {
      backendController.close();
    },
  };
}

type MsgHandler = (e: { data: unknown }) => void;

function makeFakeWs() {
  const handlers = new Map<string, MsgHandler[]>();
  const sent: ArrayBuffer[] = [];
  const ws = {
    readyState: 1,
    accept: vi.fn(),
    send(data: ArrayBuffer | Uint8Array) {
      sent.push(data instanceof Uint8Array ? data.slice().buffer as ArrayBuffer : data);
    },
    close: vi.fn(),
    addEventListener(type: string, fn: MsgHandler) {
      const arr = handlers.get(type) ?? [];
      arr.push(fn);
      handlers.set(type, arr);
    },
    emit(type: string, event: { data: unknown }) {
      for (const fn of handlers.get(type) ?? []) fn(event);
    },
  };
  return { ws, sent, handlers };
}

describe("bridgeWebSocketToTcp", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("forwards WebSocket binary -> TCP with byte integrity", async () => {
    const { tcp, written } = makeTcpPair();
    const { ws } = makeFakeWs();
    const p = bridgeWebSocketToTcp(ws as unknown as WebSocket, tcp as never, { maxMessageSize: 1 << 20 });
    const payload = new Uint8Array([1, 2, 3, 4, 5, 250, 251]);
    ws.emit("message", { data: payload });
    // Give the pump a tick, then close both sides.
    await new Promise((r) => setTimeout(r, 50));
    ws.emit("close", { data: undefined });
    const stats = await p;
    expect(stats.bytesWsToTcp).toBe(payload.byteLength);
    const total = written.reduce((n, c) => n + c.byteLength, 0);
    expect(total).toBe(payload.byteLength);
    expect(written[0]).toEqual(payload);
  });

  it("forwards TCP -> WebSocket as binary", async () => {
    const { tcp, pushFromBackend, closeBackend } = makeTcpPair();
    const { ws, sent } = makeFakeWs();
    const p = bridgeWebSocketToTcp(ws as unknown as WebSocket, tcp as never);
    pushFromBackend(new Uint8Array([9, 8, 7]));
    await new Promise((r) => setTimeout(r, 50));
    closeBackend();
    ws.emit("close", { data: undefined });
    const stats = await p;
    expect(stats.bytesTcpToWs).toBe(3);
    expect(sent.length).toBe(1);
    expect(new Uint8Array(sent[0] as ArrayBuffer)).toEqual(new Uint8Array([9, 8, 7]));
  });

  it("ignores text frames (never injects control data into the stream)", async () => {
    const { tcp, written } = makeTcpPair();
    const { ws } = makeFakeWs();
    const p = bridgeWebSocketToTcp(ws as unknown as WebSocket, tcp as never);
    ws.emit("message", { data: "hello-text-frame" });
    await new Promise((r) => setTimeout(r, 50));
    ws.emit("close", { data: undefined });
    const stats = await p;
    expect(stats.bytesWsToTcp).toBe(0);
    expect(written.length).toBe(0);
  });

  it("handles close cleanly with reason ok", async () => {
    const { tcp } = makeTcpPair();
    const { ws } = makeFakeWs();
    const p = bridgeWebSocketToTcp(ws as unknown as WebSocket, tcp as never);
    ws.emit("close", { data: undefined });
    // Also need TCP side to finish: close backend via error-free close.
    // The bridge's TCP reader pends; simulate backend EOF by cancelling.
    await tcp.readable.cancel().catch(() => {});
    const stats = await p;
    expect(["ok", "ws_closed", "tcp_eof"]).toContain(stats.reason);
  });

  it("preserves binary integrity for large fragmented payloads", async () => {
    const { tcp, written } = makeTcpPair();
    const { ws } = makeFakeWs();
    const p = bridgeWebSocketToTcp(ws as unknown as WebSocket, tcp as never, { maxMessageSize: 4 << 20 });
    const big = new Uint8Array(256 * 1024);
    for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
    // Fragment into 16 KiB WebSocket messages like the Go relay does.
    for (let off = 0; off < big.length; off += 16384) {
      ws.emit("message", { data: big.slice(off, off + 16384) });
    }
    await new Promise((r) => setTimeout(r, 200));
    ws.emit("close", { data: undefined });
    const stats = await p;
    expect(stats.bytesWsToTcp).toBe(big.length);
    let totalLen = 0;
    for (const c of written) totalLen += c.byteLength;
    expect(totalLen).toBe(big.length);
    const joined = new Uint8Array(totalLen);
    let off = 0;
    for (const c of written) {
      joined.set(c, off);
      off += c.byteLength;
    }
    expect(joined).toEqual(big);
  });
});
