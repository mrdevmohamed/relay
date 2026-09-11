import { describe, expect, it } from "vitest";
import { policyFromEnv, validateTarget, type SecurityPolicy } from "../src/security";

const denyAll: SecurityPolicy = {
  allowPrivateNetworks: false,
  allowLoopback: false,
  allowLinkLocal: false,
  allowedDomains: [],
  blockedDomains: [],
  allowedPorts: [],
};

describe("validateTarget IP literals", () => {
  it("blocks loopback", () => {
    expect(validateTarget("127.0.0.1", 443, denyAll).ok).toBe(false);
    expect(validateTarget("::1", 443, denyAll).reason).toBe("blocked_loopback");
  });
  it("blocks RFC1918", () => {
    for (const h of ["10.1.2.3", "172.16.5.4", "172.31.0.1", "192.168.1.1"]) {
      const r = validateTarget(h, 443, denyAll);
      expect(r.ok).toBe(false);
      expect(r.reason).toBe("blocked_private");
    }
  });
  it("blocks link-local and metadata IP", () => {
    expect(validateTarget("169.254.169.254", 80, denyAll).reason).toBe("blocked_link_local");
    expect(validateTarget("fe80::1", 80, denyAll).reason).toBe("blocked_link_local");
  });
  it("blocks multicast, unspecified, broadcast", () => {
    for (const h of ["224.0.0.1", "0.0.0.0", "255.255.255.255", "ff02::1"]) {
      expect(validateTarget(h, 80, denyAll).ok).toBe(false);
    }
  });
  it("blocks unique-local IPv6", () => {
    expect(validateTarget("fc00::1", 443, denyAll).reason).toBe("blocked_private");
  });
  it("applies IPv4 policy to mapped IPv6", () => {
    expect(validateTarget("::ffff:10.0.0.1", 443, denyAll).reason).toBe("blocked_private");
    expect(validateTarget("::ffff:93.184.216.34", 443, denyAll).ok).toBe(true);
  });
  it("allows public IPs", () => {
    expect(validateTarget("93.184.216.34", 443, denyAll)).toMatchObject({ ok: true });
  });
  it("honours allow toggles", () => {
    const allow = { ...denyAll, allowLoopback: true, allowPrivateNetworks: true, allowLinkLocal: true };
    expect(validateTarget("127.0.0.1", 8080, allow).ok).toBe(true);
    expect(validateTarget("10.0.0.1", 80, allow).ok).toBe(true);
    expect(validateTarget("169.254.169.254", 80, allow).ok).toBe(true);
  });
});

describe("validateTarget names", () => {
  it("blocks localhost", () => {
    expect(validateTarget("localhost", 443, denyAll).reason).toBe("blocked_loopback");
  });
  it("blocks metadata hostnames", () => {
    expect(validateTarget("metadata.google.internal", 80, denyAll).ok).toBe(false);
  });
  it("enforces blocked domains incl. subdomains", () => {
    const p = { ...denyAll, blockedDomains: ["bad.example"] };
    expect(validateTarget("sub.bad.example", 443, p).reason).toBe("blocked_domain");
    expect(validateTarget("bad.example", 443, p).reason).toBe("blocked_domain");
    expect(validateTarget("notbad.example", 443, p).ok).toBe(true);
  });
  it("enforces allowed domains", () => {
    const p = { ...denyAll, allowedDomains: ["example.com"] };
    expect(validateTarget("example.com", 443, p).ok).toBe(true);
    expect(validateTarget("sub.example.com", 443, p).ok).toBe(true);
    expect(validateTarget("other.org", 443, p).reason).toBe("domain_not_allowed");
  });
  it("allows ordinary public names", () => {
    expect(validateTarget("example.com", 443, denyAll).ok).toBe(true);
  });
});

describe("validateTarget ports", () => {
  it("rejects port 0 and 25", () => {
    expect(validateTarget("93.184.216.34", 0, denyAll).ok).toBe(false);
    expect(validateTarget("93.184.216.34", 25, denyAll).reason).toBe("blocked_port");
  });
  it("enforces allowed_ports", () => {
    const p = { ...denyAll, allowedPorts: [443, 8443] };
    expect(validateTarget("93.184.216.34", 443, p).ok).toBe(true);
    expect(validateTarget("93.184.216.34", 80, p).reason).toBe("port_not_allowed");
  });
});

describe("policyFromEnv", () => {
  it("parses toggles and lists", () => {
    const p = policyFromEnv({
      ALLOW_LOOPBACK: "true",
      ALLOWED_DOMAINS: "Example.COM, sub.example.org ",
      BLOCKED_DOMAINS: "bad.example",
      ALLOWED_PORTS: "443, 8443, bogus",
    });
    expect(p.allowLoopback).toBe(true);
    expect(p.allowPrivateNetworks).toBe(false);
    expect(p.allowedDomains).toEqual(["example.com", "sub.example.org"]);
    expect(p.blockedDomains).toEqual(["bad.example"]);
    expect(p.allowedPorts).toEqual([443, 8443]);
  });
  it("defaults to deny", () => {
    const p = policyFromEnv({});
    expect(p).toMatchObject({
      allowPrivateNetworks: false,
      allowLoopback: false,
      allowLinkLocal: false,
      allowedDomains: [],
    });
  });
});
