// Outbound TCP via the Workers runtime `cloudflare:sockets` API.
// No Node.js networking modules are used here.

import { connect } from "cloudflare:sockets";

export interface TcpConnection {
  readable: ReadableStream<Uint8Array>;
  writable: WritableStream<Uint8Array>;
  opened: Promise<unknown>;
  closed: Promise<void>;
  close: () => Promise<void>;
}

/**
 * Open an outbound TCP connection to a policy-validated hostname:port.
 * Throws on failure; callers must map errors to generic responses
 * without exposing internal host/port details.
 */
export async function openTcpConnection(hostname: string, port: number, timeoutMs = 10_000): Promise<TcpConnection> {
  const socket = connect(
    { hostname, port },
    { secureTransport: "off", allowHalfOpen: true },
  ) as unknown as TcpConnection;
  // Wait for establishment (or failure) with a timeout.
  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => reject(new Error("tcp connect timeout")), timeoutMs),
  );
  await Promise.race([socket.opened, timeout]);
  return socket;
}

/** Best-effort close that never throws. */
export async function closeTcpConnection(sock: TcpConnection | null): Promise<void> {
  if (!sock) return;
  try {
    await sock.close();
  } catch {
    // ignore
  }
}
