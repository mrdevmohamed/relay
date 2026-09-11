// Authentication helpers. The bearer token is compared without logging it
// and without ever reflecting it in responses.

/** Extract the bearer token from an Authorization header (or null). */
export function extractBearerToken(header: string | null): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(\S+)\s*$/i.exec(header.trim());
  return m ? (m[1] as string) : null;
}

/** Constant-time-ish string comparison to avoid trivial timing leaks. */
export function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

/** Validate the request's Authorization header against the expected secret. */
export function isAuthorized(request: Request, expectedToken: string): boolean {
  if (!expectedToken) return false;
  const got = extractBearerToken(request.headers.get("Authorization"));
  if (!got) return false;
  return timingSafeEqual(got, expectedToken);
}
