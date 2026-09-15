import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { deviceSigningKeyFingerprint, EnrollmentStore } from "../broker/src/enrollment-store";

/** Operator-approved fingerprint of a freshly generated device signing key. */
function deviceFingerprint(): string {
  return deviceSigningKeyFingerprint(
    generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString()
  );
}

describe("self-hosted operator enrollment codes", () => {
  it("issues a high-entropy, human-typable, hashed single-use code pre-bound to the approved device", () => {
    let largestRequest = 0;
    const store = new EnrollmentStore((size) => {
      largestRequest = Math.max(largestRequest, size);
      return Buffer.alloc(size, 5);
    });

    const issued = store.issue({ nowMs: 1_000, ttlMs: 600_000, expectedDeviceFingerprint: deviceFingerprint() });

    // At least 128 bits of entropy are drawn for the code itself.
    expect(largestRequest).toBeGreaterThanOrEqual(16);
    // Human-typable, hyphen-grouped display format.
    expect(issued.code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){1,}$/);
    expect(issued.expiresAtMs).toBe(601_000);
    // Only the hash is retained; the plaintext code is never stored.
    expect(store.debugInternalKeys()).not.toContain(issued.code);
    expect(store.debugInternalKeys().length).toBe(1);
  });

  it("requires an operator-approved device fingerprint to mint a code", () => {
    const store = new EnrollmentStore();
    // Missing, empty, malformed and non-hex fingerprints are all refused.
    expect(() => store.issue({ nowMs: 0, ttlMs: 60_000 } as never)).toThrow(/fingerprint/i);
    expect(() => store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: "" })).toThrow(/fingerprint/i);
    expect(() => store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: "not-a-fingerprint" })).toThrow(/fingerprint/i);
    expect(() => store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: "a".repeat(63) })).toThrow(/fingerprint/i);
    expect(() =>
      store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: 42 as never })
    ).toThrow(/fingerprint/i);
    // A properly formed 64-hex fingerprint is accepted (upper- or lower-case).
    expect(() => store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: deviceFingerprint().toUpperCase() })).not.toThrow();
  });

  it("bounds the enrollment TTL to 60s..1h", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    expect(() => store.issue({ nowMs: 0, ttlMs: 59_999, expectedDeviceFingerprint: fingerprint })).toThrow(/ttl/i);
    expect(() => store.issue({ nowMs: 0, ttlMs: 3_600_001, expectedDeviceFingerprint: fingerprint })).toThrow(/ttl/i);
    expect(store.issue({ nowMs: 0, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint }).expiresAtMs).toBe(60_000);
  });

  it("consumes a pre-bound code exactly once for the approved device", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    const { code } = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });

    expect(store.consume({ code, nowMs: 2_000, deviceFingerprint: fingerprint })).toEqual({ ok: true });
    expect(store.consume({ code, nowMs: 2_001, deviceFingerprint: fingerprint })).toEqual({ ok: false, reason: "used" });
  });

  it("fails closed when the pairing device fingerprint does not equal the approved fingerprint", () => {
    const store = new EnrollmentStore();
    const approved = deviceFingerprint();
    const { code } = store.issue({ nowMs: 1_000, ttlMs: 600_000, expectedDeviceFingerprint: approved });

    // A different, a missing and a malformed device fingerprint are all refused.
    expect(store.consume({ code, nowMs: 2_000, deviceFingerprint: deviceFingerprint() })).toEqual({
      ok: false,
      reason: "fingerprint_mismatch"
    });
    expect(store.consume({ code, nowMs: 2_000 })).toEqual({ ok: false, reason: "fingerprint_mismatch" });
    expect(store.consume({ code, nowMs: 2_000, deviceFingerprint: "not-a-fingerprint" })).toEqual({
      ok: false,
      reason: "fingerprint_mismatch"
    });

    // Fail-closed attempts never burn the code for the approved device.
    expect(store.consume({ code, nowMs: 2_001, deviceFingerprint: approved })).toEqual({ ok: true });
  });

  it("matches the approved fingerprint case-insensitively", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    const { code } = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint.toUpperCase() });

    expect(store.consume({ code, nowMs: 2_000, deviceFingerprint: fingerprint })).toEqual({ ok: true });
  });

  it("tolerates case and separator typography when consuming", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    const { code } = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });

    const retyped = code.toLowerCase().replace(/-/g, " ");
    expect(store.consume({ code: retyped, nowMs: 2_000, deviceFingerprint: fingerprint })).toEqual({ ok: true });
  });

  it("expires codes at the TTL boundary", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    const stillValid = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });
    expect(store.consume({ code: stillValid.code, nowMs: 60_999, deviceFingerprint: fingerprint })).toEqual({ ok: true });

    const expired = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });
    expect(store.consume({ code: expired.code, nowMs: 61_000, deviceFingerprint: fingerprint })).toEqual({
      ok: false,
      reason: "expired"
    });
  });

  it("fails closed for unknown and malformed codes", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    expect(store.consume({ code: "ZZZZ-ZZZZ-ZZZZ-ZZZZ", nowMs: 1, deviceFingerprint: fingerprint })).toEqual({
      ok: false,
      reason: "unknown"
    });
    expect(store.consume({ code: "not a real code!!", nowMs: 1, deviceFingerprint: fingerprint })).toEqual({
      ok: false,
      reason: "unknown"
    });
    expect(store.consume({ code: "", nowMs: 1, deviceFingerprint: fingerprint })).toEqual({ ok: false, reason: "unknown" });
  });

  it("enforces a capacity limit and evicts expired codes", () => {
    const store = new EnrollmentStore(undefined, 1);
    const fingerprint = deviceFingerprint();
    store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });
    expect(() => store.issue({ nowMs: 2_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint })).toThrow(/capacity/i);
    expect(() => store.issue({ nowMs: 61_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint })).not.toThrow();
    expect(store.debugCounts().count).toBe(1);
  });

  it("reports non-secret metadata only", () => {
    const store = new EnrollmentStore();
    const fingerprint = deviceFingerprint();
    const first = store.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: fingerprint });
    store.issue({ nowMs: 1_000, ttlMs: 120_000, expectedDeviceFingerprint: fingerprint });
    store.consume({ code: first.code, nowMs: 2_000, deviceFingerprint: fingerprint });

    const counts = store.debugCounts();
    expect(counts).toEqual({ count: 2, used: 1, unused: 1, expiries: [61_000, 121_000] });
    expect(JSON.stringify(counts)).not.toContain(first.code);
    expect(JSON.stringify(counts)).not.toContain(fingerprint);
  });
});
