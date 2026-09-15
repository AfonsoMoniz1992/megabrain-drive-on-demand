import { createHash, createPublicKey, randomBytes } from "node:crypto";

/**
 * Operator-issued, single-use enrollment codes.
 *
 * Threat model: a code is a short-lived bearer secret that authorizes exactly
 * one device to create a pairing. It must be infeasible to guess (at least
 * 128 bits of entropy), must never be stored in plaintext, must expire quickly,
 * and must be bound, at mint time, to the fingerprint of the device signing key
 * the operator approved. A leaked or guessed code therefore cannot be redeemed
 * by any device other than the one whose key the operator checked out of band;
 * a consumption attempt that omits or mismatches the approved fingerprint fails
 * closed and does not burn the code for the approved device.
 *
 * Only the SHA-256 hash of the canonical (normalised) code and the SHA-256 hash
 * of the approved fingerprint are retained.
 */

// Crockford-style base32 alphabet: 32 symbols, 5 bits each. Ambiguous
// characters (I, L, O, U) are excluded to keep codes human-typable.
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const BITS_PER_CHAR = 5;
const CODE_BYTES = 20; // 160 bits, rounded up to 32 base32 characters
const GROUP_SIZE = 4;
const MIN_TTL_MS = 60_000;
const MAX_TTL_MS = 60 * 60_000;
const DEFAULT_MAX_CODES = 1_000;

export type EnrollmentConsumeReason = "unknown" | "expired" | "used" | "fingerprint_mismatch";

export type EnrollmentConsumeResult = { ok: true } | { ok: false; reason: EnrollmentConsumeReason };

export interface EnrollmentMetadata {
  count: number;
  used: number;
  unused: number;
  expiries: number[];
}

interface EnrollmentRecord {
  codeHash: string;
  expiresAtMs: number;
  used: boolean;
  expectedFingerprintHash: string;
}

function encodeBase32(bytes: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= BITS_PER_CHAR) {
      output += ALPHABET[(value >>> (bits - BITS_PER_CHAR)) & 31];
      bits -= BITS_PER_CHAR;
    }
  }
  if (bits > 0) output += ALPHABET[(value << (BITS_PER_CHAR - bits)) & 31];
  return output;
}

function group(code: string): string {
  const parts: string[] = [];
  for (let index = 0; index < code.length; index += GROUP_SIZE) {
    parts.push(code.slice(index, index + GROUP_SIZE));
  }
  return parts.join("-");
}

/** Uppercases and strips separators; returns the canonical code, or "" when malformed. */
function normalise(code: unknown): string {
  if (typeof code !== "string") return "";
  const canonical = code.toUpperCase().replace(/[^0-9A-Z]/g, "");
  if (canonical.length !== (CODE_BYTES * 8) / BITS_PER_CHAR) return "";
  for (const character of canonical) {
    if (!ALPHABET.includes(character)) return "";
  }
  return canonical;
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

/** A device signing-key fingerprint is the lowercase hex SHA-256 of the DER SPKI. */
const FINGERPRINT_PATTERN = /^[0-9a-f]{64}$/;

/**
 * Normalises and hashes an operator-approved device fingerprint. Anything that
 * is not a 64-character hex digest is rejected, so an operator can never mint a
 * code that is unbound or bound to a malformed value.
 */
function fingerprintHash(value: unknown): string {
  if (typeof value !== "string") throw new Error("A device signing-key fingerprint is required");
  const normalised = value.trim().toLowerCase();
  if (!FINGERPRINT_PATTERN.test(normalised)) throw new Error("A valid device signing-key fingerprint is required");
  return hash(normalised);
}

/**
 * Stable fingerprint of a device signing key (Ed25519, SPKI PEM). Derived from
 * the DER encoding so equivalent key encodings map to one fingerprint.
 */
export function deviceSigningKeyFingerprint(devicePublicKeyPem: string): string {
  return createHash("sha256")
    .update(createPublicKey(devicePublicKeyPem).export({ type: "spki", format: "der" }))
    .digest("hex");
}

export class EnrollmentStore {
  private readonly records = new Map<string, EnrollmentRecord>();

  constructor(
    private readonly random: (size: number) => Buffer = randomBytes,
    private readonly maxCodes = DEFAULT_MAX_CODES
  ) {
    if (!Number.isInteger(maxCodes) || maxCodes < 1) throw new Error("Invalid enrollment capacity");
  }

  private evictExpired(nowMs: number): void {
    for (const [key, record] of this.records) {
      if (nowMs >= record.expiresAtMs) this.records.delete(key);
    }
  }

  /**
   * Mints a new single-use code pre-bound to the operator-approved device
   * signing-key fingerprint. The plaintext code is returned exactly once.
   */
  issue(input: {
    nowMs: number;
    ttlMs: number;
    expectedDeviceFingerprint: string;
  }): { code: string; expiresAtMs: number } {
    if (!Number.isInteger(input.nowMs) || input.nowMs < 0) throw new Error("Invalid enrollment time");
    if (!Number.isInteger(input.ttlMs) || input.ttlMs < MIN_TTL_MS || input.ttlMs > MAX_TTL_MS) {
      throw new Error("Enrollment TTL must be between 60s and 1h");
    }
    // The approved fingerprint is validated before any capacity or randomness
    // work, so an unbound code can never be created.
    const expectedFingerprintHash = fingerprintHash(input.expectedDeviceFingerprint);
    this.evictExpired(input.nowMs);
    if (this.records.size >= this.maxCodes) throw new Error("Enrollment capacity reached");

    const canonical = encodeBase32(this.random(CODE_BYTES));
    const code = group(canonical);
    const codeHash = hash(canonical);
    const expiresAtMs = input.nowMs + input.ttlMs;
    this.records.set(codeHash, { codeHash, expiresAtMs, used: false, expectedFingerprintHash });
    return { code, expiresAtMs };
  }

  /**
   * Consumes a code exactly once, but only for the device whose signing-key
   * fingerprint the operator approved. A missing or mismatching fingerprint
   * fails closed as `fingerprint_mismatch` before the code is burned, so the
   * approved device can still redeem it.
   */
  consume(input: { code: string; nowMs: number; deviceFingerprint?: string }): EnrollmentConsumeResult {
    const canonical = normalise(input.code);
    if (!canonical) return { ok: false, reason: "unknown" };
    const record = this.records.get(hash(canonical));
    if (!record) return { ok: false, reason: "unknown" };

    const providedFingerprintHash =
      typeof input.deviceFingerprint === "string" && FINGERPRINT_PATTERN.test(input.deviceFingerprint.trim().toLowerCase())
        ? hash(input.deviceFingerprint.trim().toLowerCase())
        : undefined;

    // Pre-bound approval gate: no fingerprint, a malformed fingerprint or any
    // fingerprint other than the approved one fail closed.
    if (!providedFingerprintHash || providedFingerprintHash !== record.expectedFingerprintHash) {
      return { ok: false, reason: "fingerprint_mismatch" };
    }

    if (input.nowMs >= record.expiresAtMs) {
      this.records.delete(record.codeHash);
      return { ok: false, reason: "expired" };
    }

    if (record.used) return { ok: false, reason: "used" };

    record.used = true;
    return { ok: true };
  }

  /** Non-secret operator metadata: never codes or fingerprints. */
  debugCounts(): EnrollmentMetadata {
    const records = [...this.records.values()];
    return {
      count: records.length,
      used: records.filter((record) => record.used).length,
      unused: records.filter((record) => !record.used).length,
      expiries: records.map((record) => record.expiresAtMs)
    };
  }

  /** Test-only: the stored hashes, to prove plaintext codes are never retained. */
  debugInternalKeys(): string[] {
    return [...this.records.keys()];
  }
}
