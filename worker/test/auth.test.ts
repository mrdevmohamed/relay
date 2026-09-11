import { describe, expect, it } from "vitest";
import { extractBearerToken, isAuthorized, timingSafeEqual } from "../src/auth";

function reqWithAuth(value: string | null): Request {
  const headers = new Headers();
  if (value !== null) headers.set("Authorization", value);
  return new Request("https://vpn.example.com/openvpn/egypt", { headers });
}

describe("extractBearerToken", () => {
  it("extracts a bearer token", () => {
    expect(extractBearerToken("Bearer abc123")).toBe("abc123");
  });
  it("is case-insensitive on scheme", () => {
    expect(extractBearerToken("bearer abc123")).toBe("abc123");
  });
  it("returns null when missing", () => {
    expect(extractBearerToken(null)).toBeNull();
  });
  it("rejects non-bearer schemes", () => {
    expect(extractBearerToken("Basic abc")).toBeNull();
  });
  it("rejects empty token", () => {
    expect(extractBearerToken("Bearer ")).toBeNull();
  });
});

describe("timingSafeEqual", () => {
  it("compares equal strings", () => {
    expect(timingSafeEqual("secret", "secret")).toBe(true);
  });
  it("rejects different strings", () => {
    expect(timingSafeEqual("secret", "secreu")).toBe(false);
  });
  it("rejects different lengths", () => {
    expect(timingSafeEqual("short", "longer")).toBe(false);
  });
});

describe("isAuthorized", () => {
  it("accepts a valid token", () => {
    expect(isAuthorized(reqWithAuth("Bearer s3cret"), "s3cret")).toBe(true);
  });
  it("rejects a missing header -> 401 path", () => {
    expect(isAuthorized(reqWithAuth(null), "s3cret")).toBe(false);
  });
  it("rejects an invalid token", () => {
    expect(isAuthorized(reqWithAuth("Bearer wrong"), "s3cret")).toBe(false);
  });
  it("rejects when no secret is configured", () => {
    expect(isAuthorized(reqWithAuth("Bearer x"), "")).toBe(false);
  });
  it("never reflects the token (boolean only)", () => {
    const result = isAuthorized(reqWithAuth("Bearer wrong"), "s3cret");
    expect(typeof result).toBe("boolean");
  });
});
