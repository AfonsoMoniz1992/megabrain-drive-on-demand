import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import { PairingStore } from "../broker/src/pairing-store";

function device(): { publicKey: string; signProof: (message: string) => string; privateKey: KeyObject } {
  const keys = generateKeyPairSync("ed25519");
  return {
    publicKey: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKey: keys.privateKey,
    signProof: (message) => sign(null, Buffer.from(message), keys.privateKey).toString("base64url")
  };
}

function encryption(): string {
  return generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function create(store: PairingStore, owner: { publicKey: string }, nowMs = 1_000, ttlMs = 60_000) {
  return store.create({ devicePublicKeyPem: owner.publicKey, deviceEncryptionPublicKeyPem: encryption(), nowMs, ttlMs });
}

function authorize(store: PairingStore, owner: { publicKey: string }): ReturnType<PairingStore["create"]> {
  const created = create(store, owner);
  const callback = store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 });
  if (!callback) throw new Error("callback state was not consumed");
  expect(store.markAuthorized({ callbackHandle: callback.callbackHandle, nowMs: 2_000 })).toBe(true);
  return created;
}

describe("self-hosted pairing store", () => {
  it("rejects device claims before a future authorization transition", () => {
    const store = new PairingStore(() => Buffer.alloc(32, 7));
    const d = device();
    const created = create(store, d);
    const proof = d.signProof(created.proofMessage);

    expect(store.debugRecord(created.pairId)).toEqual({ hasPlainPairId: false, status: "pending" });
    expect(store.claim({ pairId: created.pairId, proof, nowMs: 2_000 })).toBe(false);
    expect(store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 })).toBeDefined();
    expect(store.debugRecord(created.pairId)).toEqual({ hasPlainPairId: false, status: "callback_state_consumed" });
    expect(store.claim({ pairId: created.pairId, proof, nowMs: 2_001 })).toBe(false);
  });

  it("permits one device claim only after a callback-only authorization transition", () => {
    const store = new PairingStore();
    const d = device();
    const created = store.create({ devicePublicKeyPem: d.publicKey, deviceEncryptionPublicKeyPem: encryption(), nowMs: 1_000, ttlMs: 60_000 });
    const callback = store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 });
    if (!callback) throw new Error("callback state was not consumed");

    expect(store.markAuthorized({ callbackHandle: callback.callbackHandle, nowMs: 2_000 })).toBe(true);
    expect(store.debugRecord(created.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });
    expect(store.markAuthorized({ callbackHandle: callback.callbackHandle, nowMs: 2_001 })).toBe(false);
    const proof = d.signProof(created.proofMessage);
    expect(store.claim({ pairId: created.pairId, proof, nowMs: 2_002 })).toBe(true);
    expect(store.claim({ pairId: created.pairId, proof, nowMs: 2_003 })).toBe(false);
  });

  it("transitions to a durable enrolled state and exposes the device encryption key", () => {
    const store = new PairingStore();
    const d = device();
    const enc = encryption();
    const created = store.create({ devicePublicKeyPem: d.publicKey, deviceEncryptionPublicKeyPem: enc, nowMs: 1_000, ttlMs: 60_000 });
    const callback = store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 });
    if (!callback) throw new Error("callback state was not consumed");
    expect(store.markAuthorized({ callbackHandle: callback.callbackHandle, nowMs: 2_000 })).toBe(true);

    const opened = store.openClaim({ pairId: created.pairId, proof: d.signProof(created.proofMessage), nowMs: 2_002 });
    expect(opened).toEqual({ ok: true, deviceSigningPublicKeyPem: d.publicKey, deviceEncryptionPublicKeyPem: enc });
    expect(store.debugRecord(created.pairId)).toEqual({ hasPlainPairId: false, status: "enrolled" });
    expect(store.openClaim({ pairId: created.pairId, proof: d.signProof(created.proofMessage), nowMs: 2_003 })).toEqual({
      ok: false,
      reason: "not_authorized_yet"
    });
  });

  it("requires an X25519 device encryption key", () => {
    const store = new PairingStore();
    const d = device();
    const ed25519 = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
    expect(() => store.create({ devicePublicKeyPem: d.publicKey, deviceEncryptionPublicKeyPem: ed25519, nowMs: 1_000, ttlMs: 60_000 })).toThrow(/x25519/i);
    expect(() => store.create({ devicePublicKeyPem: d.publicKey, nowMs: 1_000, ttlMs: 60_000 } as never)).toThrow();
  });

  it("issues single-use, short-lived nonces only to enrolled pairings", () => {
    const store = new PairingStore();
    const d = device();
    const created = create(store, d);

    // Not enrolled yet: no nonce.
    expect(store.issueNonce({ pairId: created.pairId, nowMs: 2_000, ttlMs: 120_000 })).toEqual({ ok: false, reason: "not_authorized_yet" });

    const enrolled = authorize(store, d);
    expect(store.openClaim({ pairId: enrolled.pairId, proof: d.signProof(enrolled.proofMessage), nowMs: 2_002 }).ok).toBe(true);

    const issued = store.issueNonce({ pairId: enrolled.pairId, nowMs: 2_003, ttlMs: 120_000 });
    if (!issued.ok) throw new Error("nonce was not issued");
    expect(issued.nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(issued.expiresAtMs).toBe(122_003);

    const proof = sign(null, Buffer.from(issued.nonce, "base64url"), d.privateKey).toString("base64url");
    expect(store.consumeNonce({ pairId: enrolled.pairId, nonce: issued.nonce, proof, nowMs: 2_004 })).toMatchObject({ ok: true });
    expect(store.consumeNonce({ pairId: enrolled.pairId, nonce: issued.nonce, proof, nowMs: 2_005 })).toEqual({ ok: false, reason: "invalid_nonce" });

    const expiring = store.issueNonce({ pairId: enrolled.pairId, nowMs: 2_006, ttlMs: 1_000 });
    if (!expiring.ok) throw new Error("nonce was not issued");
    const expiredProof = sign(null, Buffer.from(expiring.nonce, "base64url"), d.privateKey).toString("base64url");
    expect(store.consumeNonce({ pairId: enrolled.pairId, nonce: expiring.nonce, proof: expiredProof, nowMs: 3_006 })).toEqual({
      ok: false,
      reason: "invalid_nonce"
    });
  });

  it("rejects a lease for a revoked pairing and clears its nonces", () => {
    const store = new PairingStore();
    const d = device();
    const created = authorize(store, d);
    expect(store.openClaim({ pairId: created.pairId, proof: d.signProof(created.proofMessage), nowMs: 2_002 }).ok).toBe(true);
    const issued = store.issueNonce({ pairId: created.pairId, nowMs: 2_003, ttlMs: 120_000 });
    if (!issued.ok) throw new Error("nonce was not issued");
    expect(store.revoke({ pairId: created.pairId, nowMs: 2_004 })).toBe(true);
    expect(store.debugRecord(created.pairId)).toEqual({ hasPlainPairId: false, status: "revoked" });
    expect(store.issueNonce({ pairId: created.pairId, nowMs: 2_005, ttlMs: 120_000 })).toEqual({ ok: false, reason: "revoked" });
    const proof = sign(null, Buffer.from(issued.nonce, "base64url"), d.privateKey).toString("base64url");
    expect(store.consumeNonce({ pairId: created.pairId, nonce: issued.nonce, proof, nowMs: 2_006 })).toEqual({ ok: false, reason: "revoked" });
  });

  it("consumes callback state once and returns its server-held PKCE verifier only to the callback path", () => {
    const store = new PairingStore();
    const d = device();
    const created = create(store, d);
    expect(created).not.toHaveProperty("pkceVerifier");
    expect(store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 })).toMatchObject({
      pkceVerifier: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/)
    });
    expect(store.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_001 })).toBeUndefined();
    const expired = create(store, d);
    expect(store.consumeOAuthState({ oauthState: expired.oauthState, nowMs: 61_000 })).toBeUndefined();
  });

  it("evicts expired records and enforces the configured pending-record limit", () => {
    const d = device();
    const store = new PairingStore(undefined, 1);
    create(store, d);
    expect(() => create(store, d, 2_000)).toThrow("Pairing capacity reached");
    expect(() => create(store, d, 61_000)).not.toThrow();
    expect(store.debugSize()).toBe(1);
  });

  it("rejects another device proof after authorization and expired claims", () => {
    const store = new PairingStore();
    const owner = device();
    const attacker = device();
    const created = authorize(store, owner);

    expect(store.claim({ pairId: created.pairId, proof: attacker.signProof(created.proofMessage), nowMs: 2_001 })).toBe(false);
    expect(store.claim({ pairId: created.pairId, proof: owner.signProof(created.proofMessage), nowMs: 2_002 })).toBe(true);

    const expired = authorize(store, owner);
    expect(store.claim({ pairId: expired.pairId, proof: owner.signProof(expired.proofMessage), nowMs: 61_000 })).toBe(false);
  });
});
