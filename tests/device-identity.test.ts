import { describe, expect, it } from "vitest";
import { createPublicKey } from "node:crypto";
import { deviceSigningKeyFingerprint } from "../broker/src/enrollment-store";
import { ed25519 } from "@noble/curves/ed25519.js";
import {
  LEASE_INFO,
  UNSEAL_INFO,
  deviceFingerprint,
  exportEd25519SpkiPem,
  exportX25519RawPublicKey,
  exportX25519SpkiPem,
  fromBase64Url,
  generateDeviceIdentity,
  sealLeaseEnvelope,
  signBase64Url,
  toBase64Url,
  unsealLease,
  type SealedEnvelope
} from "../src/auth/device-identity";

const message = new TextEncoder().encode("gdriveStreaming proof message");

describe("device identity", () => {
  it("generates a 32-byte Ed25519 and X25519 keypair", () => {
    const identity = generateDeviceIdentity();
    expect(identity.ed25519PublicKey).toHaveLength(32);
    expect(identity.ed25519PrivateKey).toHaveLength(32);
    expect(identity.x25519PublicKey).toHaveLength(32);
    expect(identity.x25519PrivateKey).toHaveLength(32);
    expect(toBase64Url(identity.ed25519PublicKey)).not.toContain("=");
  });

  it("signs bytes as base64url and verifies with the exported Ed25519 SPKI PEM", () => {
    const identity = generateDeviceIdentity();
    const proof = signBase64Url(identity, message);
    expect(proof).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(fromBase64Url(proof)).toHaveLength(64);
    expect(ed25519.verify(fromBase64Url(proof), message, identity.ed25519PublicKey)).toBe(true);
    expect(ed25519.verify(fromBase64Url(proof), new TextEncoder().encode("other"), identity.ed25519PublicKey)).toBe(false);

    const pem = exportEd25519SpkiPem(identity.ed25519PublicKey);
    expect(pem).toMatch(/^-----BEGIN PUBLIC KEY-----\n[\s\S]+\n-----END PUBLIC KEY-----$/);
    const parsed = createPublicKey({ key: pem, format: "pem" });
    expect(parsed.asymmetricKeyType).toBe("ed25519");
    const spki = parsed.export({ format: "der", type: "spki" });
    expect(toBase64Url(new Uint8Array(spki).slice(-32))).toBe(toBase64Url(identity.ed25519PublicKey));
  });

  it("exports an X25519 SPKI PEM and the raw X25519 public key", () => {
    const identity = generateDeviceIdentity();
    const pem = exportX25519SpkiPem(identity.x25519PublicKey);
    const parsed = createPublicKey({ key: pem, format: "pem" });
    expect(parsed.asymmetricKeyType).toBe("x25519");
    const raw = exportX25519RawPublicKey(identity);
    expect(raw).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Array.from(fromBase64Url(raw))).toEqual(Array.from(identity.x25519PublicKey));
  });

  it("unseals a locally sealed lease envelope with the documented KDF", () => {
    const identity = generateDeviceIdentity();
    const payload = { accessToken: "ya29.test-only", expiresAtMs: 1_700_000_000_000, scope: "drive.readonly", allowedRootName: "example-test-root" };
    const envelope = sealLeaseEnvelope(identity.x25519PublicKey, payload);
    expect(envelope.v).toBe(1);
    expect(toBase64Url(fromBase64Url(envelope.epk))).toBe(envelope.epk);
    expect(unsealLease(identity, envelope)).toEqual(payload);
    expect(UNSEAL_INFO).toBe(LEASE_INFO);
  });

  it("rejects a tampered, misdirected or re-versioned envelope without echoing plaintext", () => {
    const identity = generateDeviceIdentity();
    const other = generateDeviceIdentity();
    const payload = { accessToken: "ya29.never-log-me", expiresAtMs: 1, scope: "drive.readonly", allowedRootName: "example-test-root" };
    const envelope = sealLeaseEnvelope(identity.x25519PublicKey, payload);

    const tampered: SealedEnvelope = { ...envelope, ct: toBase64Url(new Uint8Array([...fromBase64Url(envelope.ct)].map((byte, index) => (index === 0 ? byte ^ 0xff : byte)))) };
    expect(() => unsealLease(identity, tampered)).toThrow(/unseal/i);
    expect(() => unsealLease(other, envelope)).toThrow(/unseal/i);
    expect(() => unsealLease(identity, { ...envelope, v: 2 })).toThrow(/version/i);
    try {
      unsealLease(identity, tampered);
    } catch (error) {
      expect(String(error)).not.toContain("ya29");
    }
  });

  it("derives the canonical broker-compatible SHA-256 fingerprint of the Ed25519 SPKI", () => {
    const identity = generateDeviceIdentity();
    const other = generateDeviceIdentity();
    const fingerprint = deviceFingerprint(identity);
    const pem = exportEd25519SpkiPem(identity.ed25519PublicKey);
    const brokerFingerprint = deviceSigningKeyFingerprint(pem);

    expect(fingerprint).toBe(deviceFingerprint(identity));
    expect(fingerprint).toMatch(/^[0-9a-f]{64}$/);
    expect(fingerprint).toBe(brokerFingerprint);
    expect(fingerprint).not.toBe(deviceFingerprint(other));
  });
});
