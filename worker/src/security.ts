// Destination security policy for the Worker relay.
//
// The local relay lets clients request any host:port, so the Worker must
// refuse loopback, private, link-local, multicast and cloud-metadata
// destinations by default, plus honour domain/port allow/block lists.
// This mirrors the Go security package (which additionally resolves DNS;
// the Workers runtime cannot resolve names directly, so name-based rules
// and IP-literal range checks apply here and `connect()` performs the
// final resolution at the edge).

export interface SecurityPolicy {
  allowPrivateNetworks: boolean;
  allowLoopback: boolean;
  allowLinkLocal: boolean;
  allowedDomains: string[];
  blockedDomains: string[];
  allowedPorts: number[];
}

export interface WorkerSecurityEnv {
  ALLOW_PRIVATE_NETWORKS?: string;
  ALLOW_LOOPBACK?: string;
  ALLOW_LINK_LOCAL?: string;
  ALLOWED_DOMAINS?: string;
  BLOCKED_DOMAINS?: string;
  ALLOWED_PORTS?: string;
}

export type BlockReason =
  | "invalid_host"
  | "invalid_port"
  | "blocked_port"
  | "blocked_loopback"
  | "blocked_private"
  | "blocked_link_local"
  | "blocked_range"
  | "blocked_domain"
  | "domain_not_allowed"
  | "port_not_allowed";

/** Build a policy from Worker env vars (all optional). */
export function policyFromEnv(env: Partial<WorkerSecurityEnv>): SecurityPolicy {
  const truthy = (v: string | undefined): boolean => {
    const s = (v ?? "").trim().toLowerCase();
    return s === "true" || s === "1" || s === "yes";
  };
  const list = (v: string | undefined): string[] =>
    (v ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase().replace(/\.$/, ""))
      .filter((s) => s.length > 0);
  const ports = (v: string | undefined): number[] =>
    (v ?? "")
      .split(",")
      .map((s) => parseInt(s.trim(), 10))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
  return {
    allowPrivateNetworks: truthy(env.ALLOW_PRIVATE_NETWORKS),
    allowLoopback: truthy(env.ALLOW_LOOPBACK),
    allowLinkLocal: truthy(env.ALLOW_LINK_LOCAL),
    allowedDomains: list(env.ALLOWED_DOMAINS),
    blockedDomains: list(env.BLOCKED_DOMAINS),
    allowedPorts: ports(env.ALLOWED_PORTS),
  };
}

export interface ValidationResult {
  ok: boolean;
  reason?: BlockReason;
  /** Normalized host for logging (never a secret; hosts are client-chosen routing data). */
  host?: string;
  port?: number;
}

/** Validate a requested destination. Pure function; no I/O. */
export function validateTarget(host: string, port: number, policy: SecurityPolicy): ValidationResult {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    return { ok: false, reason: "invalid_port" };
  }
  if (port === 25) {
    return { ok: false, reason: "blocked_port" };
  }
  if (policy.allowedPorts.length > 0 && !policy.allowedPorts.includes(port)) {
    return { ok: false, reason: "port_not_allowed" };
  }
  const name = host.trim().toLowerCase().replace(/\.$/, "");
  if (name.length === 0 || name.length > 253) {
    return { ok: false, reason: "invalid_host" };
  }
  // Domain allow/block lists first (apply to names; IP literals skip them
  // unless they textually match, which is harmless).
  for (const b of policy.blockedDomains) {
    if (domainMatch(name, b)) return { ok: false, reason: "blocked_domain" };
  }
  if (policy.allowedDomains.length > 0) {
    // IP literals bypass the domain allowlist only when no allowlist match
    // is possible: check literal ranges below instead. A literal can never
    // be a "domain", so require explicit range permission via toggles.
    if (!isIpLiteral(name) && !policy.allowedDomains.some((a) => domainMatch(name, a))) {
      return { ok: false, reason: "domain_not_allowed" };
    }
  }
  if (name === "localhost" || name.endsWith(".localhost")) {
    if (!policy.allowLoopback) return { ok: false, reason: "blocked_loopback" };
    return { ok: true, host: name, port };
  }
  if (
    name === "metadata.google.internal" ||
    name === "metadata.goog" ||
    name === "instance-data" ||
    name === "instance-data.compute.internal"
  ) {
    return { ok: false, reason: "blocked_domain" };
  }
  const ipv4 = parseIPv4(name);
  if (ipv4) {
    const r = checkIPv4(ipv4, policy);
    if (!r.ok) return r;
    return { ok: true, host: name, port };
  }
  const ipv6 = parseIPv6(name);
  if (ipv6) {
    const r = checkIPv6(name, ipv6, policy);
    if (!r.ok) return r;
    return { ok: true, host: name, port };
  }
  // Ordinary domain name: allowed (edge connect() resolves; literal-range
  // policy cannot apply until resolution, which the runtime performs).
  return { ok: true, host: name, port };
}

function domainMatch(host: string, domain: string): boolean {
  const d = domain.trim().toLowerCase().replace(/\.$/, "");
  if (!d) return false;
  return host === d || host.endsWith("." + d);
}

function isIpLiteral(name: string): boolean {
  return parseIPv4(name) !== null || parseIPv6(name) !== null;
}

function parseIPv4(name: string): [number, number, number, number] | null {
  const parts = name.split(".");
  if (parts.length !== 4) return null;
  const out: number[] = [];
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = parseInt(p, 10);
    if (n < 0 || n > 255) return null;
    out.push(n);
  }
  return [out[0] as number, out[1] as number, out[2] as number, out[3] as number];
}

function checkIPv4(ip: [number, number, number, number], policy: SecurityPolicy): ValidationResult {
  const [a, b] = ip;
  const inLoopback = a === 127;
  const inPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  const inLinkLocal = a === 169 && b === 254;
  const inUnspecified = a === 0;
  const inMulticast = a >= 224 && a <= 239;
  const inBroadcast = a === 255;
  if (inLoopback) {
    return policy.allowLoopback ? { ok: true } : { ok: false, reason: "blocked_loopback" };
  }
  if (inLinkLocal) {
    return policy.allowLinkLocal ? { ok: true } : { ok: false, reason: "blocked_link_local" };
  }
  if (inPrivate) {
    return policy.allowPrivateNetworks ? { ok: true } : { ok: false, reason: "blocked_private" };
  }
  if (inUnspecified || inMulticast || inBroadcast) {
    return { ok: false, reason: "blocked_range" };
  }
  return { ok: true };
}

// Minimal IPv6 parser sufficient for range checks (handles "::" compression).
function parseIPv6(name: string): Uint16Array | null {
  let s = name;
  if (s.startsWith("[") && s.endsWith("]")) s = s.slice(1, -1);
  if (!s.includes(":")) return null;
  // Embedded IPv4 (e.g. ::ffff:1.2.3.4).
  let tail: number[] | null = null;
  const lastColon = s.lastIndexOf(":");
  const after = s.slice(lastColon + 1);
  if (after.includes(".")) {
    const v4 = parseIPv4(after);
    if (!v4) return null;
    tail = [(v4[0] * 256 + v4[1]) as number, (v4[2] * 256 + v4[3]) as number];
    s = s.slice(0, lastColon);
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parseGroup = (g: string): number[] | null => {
    if (g === "") return [];
    const out: number[] = [];
    for (const part of g.split(":")) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
      out.push(parseInt(part, 16));
    }
    return out;
  };
  let groups: number[];
  if (halves.length === 2) {
    const left = parseGroup(halves[0] as string);
    const right = parseGroup(halves[1] as string);
    if (!left || !right) return null;
    const zeros = 8 - left.length - right.length - (tail ? 2 : 0);
    if (zeros < 0) return null;
    groups = [...left, ...new Array<number>(zeros).fill(0), ...right];
  } else {
    const g = parseGroup(s);
    if (!g || g.length !== (tail ? 6 : 8)) return null;
    groups = g;
  }
  if (tail) groups = [...groups, ...tail];
  if (groups.length !== 8) return null;
  return new Uint16Array(groups);
}

function checkIPv6(name: string, g: Uint16Array, policy: SecurityPolicy): ValidationResult {
  const isZero = (i: number): boolean => (g[i] as number) === 0;
  const allZero = isZero(0) && isZero(1) && isZero(2) && isZero(3) && isZero(4) && isZero(5) && isZero(6) && isZero(7);
  // ::1 loopback, :: unspecified.
  if (allZero) return { ok: false, reason: "blocked_range" };
  if (isZero(0) && isZero(1) && isZero(2) && isZero(3) && isZero(4) && isZero(5) && isZero(6) && g[7] === 1) {
    return policy.allowLoopback ? { ok: true } : { ok: false, reason: "blocked_loopback" };
  }
  void name;
  const first = g[0] as number;
  // fe80::/10 link-local.
  if ((first & 0xffc0) === 0xfe80) {
    return policy.allowLinkLocal ? { ok: true } : { ok: false, reason: "blocked_link_local" };
  }
  // fc00::/7 unique local.
  if ((first & 0xfe00) === 0xfc00) {
    return policy.allowPrivateNetworks ? { ok: true } : { ok: false, reason: "blocked_private" };
  }
  // ff00::/8 multicast.
  if ((first & 0xff00) === 0xff00) {
    return { ok: false, reason: "blocked_range" };
  }
  // ::ffff:0:0/96 IPv4-mapped: apply the embedded IPv4 policy.
  if (isZero(0) && isZero(1) && isZero(2) && isZero(3) && isZero(4) && g[5] === 0xffff) {
    const a = ((g[6] as number) >> 8) & 0xff;
    const b = (g[6] as number) & 0xff;
    const c = ((g[7] as number) >> 8) & 0xff;
    const d = (g[7] as number) & 0xff;
    return checkIPv4([a, b, c, d], policy);
  }
  return { ok: true };
}
