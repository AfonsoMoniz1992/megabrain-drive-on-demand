import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { sealLease, unsealLease } from "../broker/src/lease-sealer";

function x25519(): { publicKeyPem: string; privateKeyPem: string } {
  const keys = generateKeyPairSync("x25519");
  return {
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

describe("device-bound lease sealer", () => {
  it("seals a JSON payload to the device and round-trips with the device key", () => {
    const device = x25519();
    const envelope = sealLease({
      payload: { accessToken: "ya29.super-secret-access-token", expiresAtMs: 123_456, allowedRootName: "example-test-root" },
      deviceEncryptionPublicKeyPem: device.publicKeyPem
    });

    expect(envelope.v).toBe(1);
    expect(envelope.epk).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(envelope.salt).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(envelope.nonce).toMatch(/^[A-Za-z0-9_-]{16}$/);

    // The plaintext payload never appears in the envelope.
    expect(JSON.stringify(envelope)).not.toContain("ya29.super-secret-access-token");

    expect(
      unsealLease({ envelope, deviceEncryptionPrivateKeyPem: device.privateKeyPem })
    ).toEqual({ accessToken: "ya29.super-secret-access-token", expiresAtMs: 123_456, allowedRootName: "example-test-root" });
  });

  it("uses a fresh ephemeral key, salt and nonce for every sealing", () => {
    const device = x25519();
    const first = sealLease({ payload: { a: 1 }, deviceEncryptionPublicKeyPem: device.publicKeyPem });
    const second = sealLease({ payload: { a: 1 }, deviceEncryptionPublicKeyPem: device.publicKeyPem });

    expect(first.epk).not.toBe(second.epk);
    expect(first.salt).not.toBe(second.salt);
    expect(first.nonce).not.toBe(second.nonce);
    expect(first.ct).not.toBe(second.ct);
  });

  it("fails to unseal with the wrong device encryption key", () => {
    const device = x25519();
    const other = x25519();
    const envelope = sealLease({ payload: { accessToken: "secret" }, deviceEncryptionPublicKeyPem: device.publicKeyPem });

    expect(() => unsealLease({ envelope, deviceEncryptionPrivateKeyPem: other.privateKeyPem })).toThrow();
  });

  it("rejects a non-X25519 device encryption key", () => {
    const ed25519 = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => sealLease({ payload: { a: 1 }, deviceEncryptionPublicKeyPem: ed25519 })).toThrow(/x25519/i);
  });
});
