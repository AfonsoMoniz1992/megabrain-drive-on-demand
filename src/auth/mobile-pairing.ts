export interface PairingChallenge {
  pairId: string;
  devicePublicKey: string;
  expiresAtMs: number;
}

export interface PairingClaimAttempt {
  pairId: string;
  devicePublicKey: string;
  nowMs: number;
}

/** The plugin may use only a clean HTTPS broker origin; OAuth callback is server-fixed. */
export function validateBrokerUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("Broker URL is invalid"); }
  if (url.protocol !== "https:") throw new Error("Broker URL must use HTTPS");
  if (url.username || url.password) throw new Error("Broker URL must not contain credentials");
  if (url.pathname !== "/" || url.search || url.hash) throw new Error("Broker URL must be an origin only");
  return url.origin;
}

/** Pair IDs are 32 random bytes represented as 64 hexadecimal characters. */
export function validatePairId(pairId: string): string {
  if (!/^[a-f0-9]{64}$/i.test(pairId)) throw new Error("Pairing ID must be a 256-bit hexadecimal value");
  return pairId;
}

/**
 * Broker *base* URL for the mobile beta: HTTPS, optional fixed service path
 * (e.g. `/gdrive-stream-oauth`), but never credentials, query, fragment or
 * traversal. Returns the normalised base without a trailing slash.
 */
export function validateBrokerBaseUrl(value: string): string {
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("Broker URL is invalid"); }
  if (url.protocol !== "https:") throw new Error("Broker URL must use HTTPS");
  if (url.username || url.password) throw new Error("Broker URL must not contain credentials");
  if (url.search || url.hash) throw new Error("Broker URL must not contain a query or fragment");
  // The URL parser silently resolves `..` segments, so inspect the raw path too.
  const rawPath = /^[a-z][a-z0-9+.-]*:\/\/[^/?#]*(\/[^?#]*)?/i.exec(value)?.[1] ?? "/";
  const traversal = rawPath.split("/").some((segment) => {
    let decoded = segment;
    try { decoded = decodeURIComponent(segment); } catch { decoded = segment; }
    return decoded === ".." || decoded === ".";
  });
  if (traversal) throw new Error("Broker URL must not contain path traversal");
  const path = url.pathname.replace(/\/+$/, "");
  return `${url.origin}${path}`;
}

function validateDevicePublicKey(value: string): string {
  if (!/^[A-Za-z0-9_-]{43,}$/.test(value)) throw new Error("Device public key is invalid");
  return value;
}

export function createPairingChallenge(input: { pairId: string; devicePublicKey: string; nowMs: number; ttlMs: number }): PairingChallenge {
  const pairId = validatePairId(input.pairId);
  const devicePublicKey = validateDevicePublicKey(input.devicePublicKey);
  if (!Number.isInteger(input.nowMs) || !Number.isInteger(input.ttlMs) || input.ttlMs <= 0 || input.ttlMs > 10 * 60_000) {
    throw new Error("Pairing expiry is invalid");
  }
  return { pairId, devicePublicKey, expiresAtMs: input.nowMs + input.ttlMs };
}

/** Claiming remains impossible without broker-side proof-of-possession verification. */
export function isClaimablePairing(challenge: PairingChallenge, attempt: PairingClaimAttempt): boolean {
  return attempt.nowMs < challenge.expiresAtMs
    && attempt.pairId === challenge.pairId
    && attempt.devicePublicKey === challenge.devicePublicKey;
}
