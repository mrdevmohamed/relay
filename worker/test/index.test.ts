import { describe, expect, it, vi, beforeEach } from "vitest";
import worker, { __resetActiveConnectionsForTest, __setActiveConnectionsForTest } from "../src/index";
import { openTcpConnection } from "../src/tcp";
import { bridgeWebSocketToTcp } from "../src/relay";

vi.mock("../src/tcp", () => ({
  openTcpConnection: vi.fn(async () => ({
    readable: new ReadableStream<Uint8Array>({ start(c) { c.close(); } }),
    writable: new WritableStream<Uint8Array>(),
    opened: Promise.resolve({}),
    closed: Promise.resolve(),
    close: async () => {},
  })),
  closeTcpConnection: vi.fn(async () => {}),
}));

vi.mock("../src/relay", () => ({
  bridgeWebSocketToTcp: vi.fn(async () => ({ bytesWsToTcp: 0, bytesTcpToWs: 0, reason: "ok" })),
}));

const env = {
  RELAY_TOKEN: "s3cret",
  MAX_CONNECTIONS: "100",
} as never;

const ctx = { waitUntil: (p: Promise<unknown>) => { void p; }, passThroughOnException: () => {} } as unknown as ExecutionContext;

function get(path: string, headers: Record<string, string> = {}): Request {
  return new Request(`https://proxy.example.com${path}`, { method: "GET", headers: new Headers(headers) });
}

type FakeSocket = {
  sent: string[];
  closed: Array<{ code?: number; reason?: string }>;
  accept: ReturnType<typeof vi.fn>;
  handlers: Map<string, Array<(e: { data?: unknown }) => void>>;
  emit(type: string, event: { data?: unknown }): void;
};

function makeSocket(): FakeSocket {
  const handlers = new Map<string, Array<(e: { data?: unknown }) => void>>();
  const sock: FakeSocket = {
    sent: [],
    closed: [],
    accept: vi.fn(),
    handlers,
    emit(type: string, event: { data?: unknown }) {
      for (const fn of handlers.get(type) ?? []) fn(event);
    },
  };
  return sock;
}

// Installs WebSocketPair + Response stubs for the node test env and returns
// access to the created pairs. The real 101 behavior is covered by
// `wrangler deploy --dry-run` and the workerd runtime.
function stubRuntime() {
  const OrigResponse = globalThis.Response;
  const pairs: Array<{ client: FakeSocket; server: FakeSocket }> = [];
  const withSocketMethods = (s: FakeSocket): FakeSocket =>
    Object.assign(s, {
      send(data: string) {
        s.sent.push(String(data));
      },
      close(code?: number, reason?: string) {
        s.closed.push({ code, reason });
      },
      binaryType: "arraybuffer",
      addEventListener(t: string, fn: (e: { data?: unknown }) => void) {
        const arr = s.handlers.get(t) ?? [];
        arr.push(fn);
        s.handlers.set(t, arr);
      },
    });
  class FakeResponse {
    status: number;
    webSocket: unknown;
    constructor(_body: unknown, init: { status: number; webSocket?: unknown }) {
      this.status = init.status;
      this.webSocket = init.webSocket;
    }
    async text(): Promise<string> {
      return "";
    }
  }
  (globalThis as unknown as Record<string, unknown>).Response = FakeResponse;
  (globalThis as unknown as Record<string, unknown>).WebSocketPair = class {
    0: unknown;
    1: unknown;
    constructor() {
      const client = withSocketMethods(makeSocket());
      const server = withSocketMethods(makeSocket());
      pairs.push({ client, server });
      this[0] = client;
      this[1] = server;
    }
  };
  if (!("randomUUID" in crypto)) {
    (crypto as unknown as Record<string, unknown>).randomUUID = () => "test-id-1234";
  }
  return {
    pairs,
    restore() {
      (globalThis as unknown as Record<string, unknown>).Response = OrigResponse;
      delete (globalThis as unknown as Record<string, unknown>).WebSocketPair;
      __resetActiveConnectionsForTest();
    },
  };
}

const wsHeaders = { Upgrade: "websocket", Authorization: "Bearer s3cret" };
const flush = (ms = 50): Promise<void> => new Promise((r) => setTimeout(r, ms));

describe("Worker request handling", () => {
  beforeEach(() => {
    __resetActiveConnectionsForTest();
    vi.clearAllMocks();
  });

  it("returns 426 for HTTP without WebSocket upgrade", async () => {
    const res = await worker.fetch(get("/connect"), env, ctx);
    expect(res.status).toBe(426);
  });

  it("returns 401 for missing Authorization", async () => {
    const res = await worker.fetch(get("/connect", { Upgrade: "websocket" }), env, ctx);
    expect(res.status).toBe(401);
  });

  it("returns 401 for invalid Authorization (and never reflects the token)", async () => {
    const res = await worker.fetch(
      get("/connect", { Upgrade: "websocket", Authorization: "Bearer wrong" }),
      env,
      ctx,
    );
    expect(res.status).toBe(401);
    const body = await res.text();
    expect(body).not.toContain("s3cret");
  });

  it("returns 404 for unknown path", async () => {
    const res = await worker.fetch(get("/nope", { Upgrade: "websocket", Authorization: "Bearer s3cret" }), env, ctx);
    expect(res.status).toBe(404);
  });

  it("accepts /connect sub-paths", async () => {
    const rt = stubRuntime();
    try {
      for (const p of ["/connect", "/connect/eu", "/connect/us"]) {
        const res = await worker.fetch(get(p, wsHeaders), env, ctx);
        expect(res.status).toBe(101);
      }
    } finally {
      rt.restore();
    }
  });

  it("returns 503 when over the connection limit", async () => {
    __setActiveConnectionsForTest(100);
    const res = await worker.fetch(get("/connect", wsHeaders), env, ctx);
    expect(res.status).toBe(503);
    __resetActiveConnectionsForTest();
  });

  it("returns 405 for non-GET methods", async () => {
    const req = new Request("https://proxy.example.com/connect", {
      method: "POST",
      headers: new Headers(wsHeaders),
    });
    const res = await worker.fetch(req, env, ctx);
    expect(res.status).toBe(405);
  });

  it("completes a valid session: connect -> connected -> bridge", async () => {
    const rt = stubRuntime();
    try {
      const res = await worker.fetch(get("/connect", wsHeaders), env, ctx);
      expect(res.status).toBe(101);
      const server = rt.pairs[0]?.server;
      expect(server).toBeDefined();
      server?.emit("message", { data: '{"type":"connect","host":"example.com","port":443}' });
      await flush();
      expect(server?.sent).toContain('{"type":"connected"}');
      expect(vi.mocked(openTcpConnection)).toHaveBeenCalledWith("example.com", 443, 10_000);
      expect(vi.mocked(bridgeWebSocketToTcp)).toHaveBeenCalled();
    } finally {
      rt.restore();
    }
  });

  it("rejects blocked destinations with an error control message", async () => {
    const rt = stubRuntime();
    try {
      const res = await worker.fetch(get("/connect", wsHeaders), env, ctx);
      expect(res.status).toBe(101);
      const server = rt.pairs[0]?.server;
      server?.emit("message", { data: '{"type":"connect","host":"10.0.0.1","port":443}' });
      await flush();
      expect(server?.sent.some((s) => s.includes('"blocked_destination"'))).toBe(true);
      expect(server?.closed.length).toBeGreaterThan(0);
      expect(vi.mocked(bridgeWebSocketToTcp)).not.toHaveBeenCalled();
    } finally {
      rt.restore();
    }
  });

  it("rejects invalid control messages with an error control message", async () => {
    const rt = stubRuntime();
    try {
      await worker.fetch(get("/connect", wsHeaders), env, ctx);
      const server = rt.pairs[0]?.server;
      server?.emit("message", { data: '{"type":"nope"}' });
      await flush();
      expect(server?.sent.some((s) => s.includes('"bad_request"'))).toBe(true);
      expect(vi.mocked(bridgeWebSocketToTcp)).not.toHaveBeenCalled();
    } finally {
      rt.restore();
    }
  });

  it("reports TCP dial failure via control message (without leaking internals)", async () => {
    vi.mocked(openTcpConnection).mockRejectedValueOnce(new Error("dial 203.0.113.10:1194 refused"));
    const rt = stubRuntime();
    try {
      await worker.fetch(get("/connect", wsHeaders), env, ctx);
      const server = rt.pairs[rt.pairs.length - 1]?.server;
      server?.emit("message", { data: '{"type":"connect","host":"example.com","port":443}' });
      await flush();
      const errMsg = server?.sent.find((s) => s.includes('"error"'));
      expect(errMsg).toContain('"tcp_failed"');
      expect(errMsg).not.toContain("203.0.113.10");
      expect(errMsg).not.toContain("s3cret");
    } finally {
      rt.restore();
    }
  });
});
