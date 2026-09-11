import { describe, expect, it, vi } from "vitest";
import {
  connectedMessage,
  errorMessage,
  parseConnectRequest,
  readConnectRequest,
} from "../src/protocol";

describe("parseConnectRequest", () => {
  it("accepts a valid connect message", () => {
    expect(parseConnectRequest('{"type":"connect","host":"example.com","port":443}')).toEqual({
      type: "connect",
      host: "example.com",
      port: 443,
    });
  });
  it("rejects non-text input", () => {
    expect(parseConnectRequest(new ArrayBuffer(4))).toBeNull();
  });
  it("rejects malformed JSON", () => {
    expect(parseConnectRequest("{nope")).toBeNull();
  });
  it("rejects wrong type", () => {
    expect(parseConnectRequest('{"type":"connected"}')).toBeNull();
  });
  it("rejects missing/empty host", () => {
    expect(parseConnectRequest('{"type":"connect","port":443}')).toBeNull();
    expect(parseConnectRequest('{"type":"connect","host":"  ","port":443}')).toBeNull();
  });
  it("rejects bad ports", () => {
    for (const p of ["443", 0, 70000, 1.5, null]) {
      expect(parseConnectRequest(`{"type":"connect","host":"h","port":${JSON.stringify(p)}}`)).toBeNull();
    }
  });
});

describe("control message encoding", () => {
  it("encodes connected", () => {
    expect(JSON.parse(connectedMessage())).toEqual({ type: "connected" });
  });
  it("encodes errors without secrets", () => {
    const m = JSON.parse(errorMessage("blocked_destination", "destination not allowed")) as Record<string, string>;
    expect(m["type"]).toBe("error");
    expect(m["code"]).toBe("blocked_destination");
  });
});

function fakeWs() {
  const handlers = new Map<string, Array<(e: { data?: unknown }) => void>>();
  return {
    sent: [] as string[],
    send(data: string) {
      this.sent.push(data);
    },
    close: vi.fn(),
    addEventListener(type: string, fn: (e: { data?: unknown }) => void) {
      const arr = handlers.get(type) ?? [];
      arr.push(fn);
      handlers.set(type, arr);
    },
    emit(type: string, event: { data?: unknown }) {
      for (const fn of handlers.get(type) ?? []) fn(event);
    },
  };
}

describe("readConnectRequest", () => {
  it("resolves on a valid text message", async () => {
    const ws = fakeWs();
    const p = readConnectRequest(ws as never, 1000);
    ws.emit("message", { data: '{"type":"connect","host":"example.com","port":443}' });
    await expect(p).resolves.toEqual({ type: "connect", host: "example.com", port: 443 });
  });
  it("ignores binary frames while waiting", async () => {
    const ws = fakeWs();
    const p = readConnectRequest(ws as never, 1000);
    ws.emit("message", { data: new Uint8Array([1, 2, 3]) });
    ws.emit("message", { data: '{"type":"connect","host":"h","port":80}' });
    await expect(p).resolves.toMatchObject({ host: "h", port: 80 });
  });
  it("rejects invalid control JSON", async () => {
    const ws = fakeWs();
    const p = readConnectRequest(ws as never, 1000);
    ws.emit("message", { data: '{"type":"nope"}' });
    await expect(p).rejects.toThrow("bad_request");
  });
  it("rejects on close", async () => {
    const ws = fakeWs();
    const p = readConnectRequest(ws as never, 1000);
    ws.emit("close", {});
    await expect(p).rejects.toThrow("closed");
  });
});
