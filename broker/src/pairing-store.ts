import { createHash, createPublicKey, randomBytes, verify, type KeyObject } from "node:crypto";

export type PairingStatus = "pending" | "callback_state_consumed" | "authorized" | "enrolled" | "revoked";

type Status = PairingStatus;

interface RecordState {
  devicePublicKey: KeyObject;
  deviceSigningPublicKeyPem: string;
  deviceEncryptionPublicKey: KeyObject;
  deviceEncryptionPublicKeyPem: string;
  expiresAtMs: number;
  proofMessage: string;
  oauthStateHash: string;
  pkceVerifier: string;
  callbackHandleHash?: string;
  status: Status;
}

interface NonceState {
  pairKeyHash: string;
  expiresAtMs: number;
}

export interface CreatedPairing {
  pairId: string;
  oauthState: string;
  proofMessage: string;
  expiresAtMs: number;
  authorizationUrl?: string;
}

export interface ConsumedOAuthState {
  callbackHandle: string;
  pkceVerifier: string;
  expiresAtMs: number;
}

export type ClaimRejection = "unknown" | "revoked" | "expired" | "not_authorized_yet" | "invalid_proof";

export type ClaimResult =
  | { ok: true; deviceSigningPublicKeyPem: string; deviceEncryptionPublicKeyPem: string }
  | { ok: false; reason: ClaimRejection };

export type NonceRejection = "unknown" | "revoked" | "not_authorized_yet";

export type IssueNonceResult = { ok: true; nonce: string; expiresAtMs: number } | { ok: false; reason: NonceRejection };

export type LeaseRejection = "unknown" | "revoked" | "expired" | "not_authorized_yet" | "invalid_nonce" | "invalid_proof";

export type ConsumeNonceResult =
  | { ok: true; deviceEncryptionPublicKeyPem: string }
  | { ok: false; reason: LeaseRejection };

const MAX_PAIRING_TTL_MS = 10 * 60_000;
const MAX_NONCE_TTL_MS = 120_000;

const pairHash = (pairId: string): string => createHash("sha256").update(pairId).digest("hex");
const stateHash = (value: string): string => createHash("sha256").update(value).digest("hex");
const encode = (bytes: Buffer): string => bytes.toString("base64url");

/**
 * In-memory, short-lived pairing handshake state. Google credentials/tokens
 * intentionally do not belong in this store; a future protected credential
 * component owns them.
 *
 * Lifecycle: pending -> callback_state_consumed -> authorized -> enrolled, with
 * `revoked` reachable by operator action at any point. This store is the
 * handshake authority only: it is deliberately ephemeral, so the durable
 * post-enrollment record that survives a broker restart and the pairing TTL
 * lives in the enrollment record store.
 */
export class PairingStore {
  private readonly records = new Map<string, RecordState>();
  private readonly states = new Map<string, string>();
  private readonly callbackHandles = new Map<string, string>();
  private readonly nonces = new Map<string, NonceState>();

  constructor(
    private readonly random: (size: number) => Buffer = randomBytes,
    private readonly maxRecords = 500
  ) {
    if (!Number.isInteger(maxRecords) || maxRecords < 1) throw new Error("Invalid pairing capacity");
  }

  private evictExpired(nowMs: number): void {
    for (const [key, record] of this.records) {
      if (nowMs >= record.expiresAtMs) {
        this.records.delete(key);
        this.states.delete(record.oauthStateHash);
        if (record.callbackHandleHash) this.callbackHandles.delete(record.callbackHandleHash);
        this.dropNoncesFor(key);
      }
    }
  }

  private evictExpiredNonces(nowMs: number): void {
    for (const [hash, nonce] of this.nonces) {
      if (nowMs >= nonce.expiresAtMs) this.nonces.delete(hash);
    }
  }

  private dropNoncesFor(pairKeyHash: string): void {
    for (const [hash, nonce] of this.nonces) {
      if (nonce.pairKeyHash === pairKeyHash) this.nonces.delete(hash);
    }
  }

  create(input: {
    devicePublicKeyPem: string;
    deviceEncryptionPublicKeyPem: string;
    nowMs: number;
    ttlMs: number;
    authorizationUrlFor?: (values: { oauthState: string; pkceVerifier: string }) => string;
  }): CreatedPairing {
    if (!Number.isInteger(input.nowMs) || !Number.isInteger(input.ttlMs) || input.ttlMs <= 0 || input.ttlMs > MAX_PAIRING_TTL_MS) {
      throw new Error("Invalid pairing expiry");
    }
    this.evictExpired(input.nowMs);
    if (this.records.size >= this.maxRecords) throw new Error("Pairing capacity reached");
    const devicePublicKey = createPublicKey(input.devicePublicKeyPem);
    if (devicePublicKey.asymmetricKeyType !== "ed25519") throw new Error("Pairing device key must be Ed25519");
    const deviceEncryptionPublicKey = createPublicKey(input.deviceEncryptionPublicKeyPem);
    if (deviceEncryptionPublicKey.asymmetricKeyType !== "x25519") throw new Error("Pairing device encryption key must be X25519");
    const pairId = this.random(32).toString("hex");
    const oauthState = encode(this.random(32));
    const pkceVerifier = encode(this.random(32));
    const expiresAtMs = input.nowMs + input.ttlMs;
    const proofMessage = `gdrive-stream-pair-v1:${pairHash(pairId)}:${expiresAtMs}`;
    const oauthStateHash = stateHash(oauthState);
    const key = pairHash(pairId);
    this.records.set(key, {
      devicePublicKey,
      deviceSigningPublicKeyPem: input.devicePublicKeyPem,
      deviceEncryptionPublicKey,
      deviceEncryptionPublicKeyPem: input.deviceEncryptionPublicKeyPem,
      expiresAtMs,
      proofMessage,
      oauthStateHash,
      pkceVerifier,
      status: "pending"
    });
    this.states.set(oauthStateHash, key);
    const authorizationUrl = input.authorizationUrlFor?.({ oauthState, pkceVerifier });
    return { pairId, oauthState, proofMessage, expiresAtMs, ...(authorizationUrl ? { authorizationUrl } : {}) };
  }

  /** Consumes the opaque callback state exactly once, bound to an unexpired pairing. */
  consumeOAuthState(input: { oauthState: string; nowMs: number }): ConsumedOAuthState | undefined {
    this.evictExpired(input.nowMs);
    const hashedState = stateHash(input.oauthState);
    const key = this.states.get(hashedState);
    if (!key) return undefined;
    const record = this.records.get(key);
    if (!record || record.oauthStateHash !== hashedState || record.status !== "pending") return undefined;
    this.states.delete(hashedState);
    const callbackHandle = encode(this.random(32));
    record.callbackHandleHash = stateHash(callbackHandle);
    this.callbackHandles.set(record.callbackHandleHash, key);
    record.status = "callback_state_consumed";
    return { callbackHandle, pkceVerifier: record.pkceVerifier, expiresAtMs: record.expiresAtMs };
  }

  /**
   * Callback-only transition: invoke this only after a future callback handler
   * has completed its provider-success checks. This gates pairing state; it is
   * not a device-approval policy.
   */
  markAuthorized(input: { callbackHandle: string; nowMs: number }): boolean {
    this.evictExpired(input.nowMs);
    const callbackHandleHash = stateHash(input.callbackHandle);
    const key = this.callbackHandles.get(callbackHandleHash);
    if (!key) return false;
    const record = this.records.get(key);
    if (!record || record.status !== "callback_state_consumed" || record.callbackHandleHash !== callbackHandleHash) return false;
    this.callbackHandles.delete(callbackHandleHash);
    record.callbackHandleHash = undefined;
    record.status = "authorized";
    return true;
  }

  /**
   * One-time claim. Requires status exactly "authorized", a valid Ed25519 proof
   * over the pairing message and an unexpired pairing. On success the pairing
   * transitions to the durable "enrolled" state and the device encryption key is
   * returned so the caller can seal the first lease. Expiry is checked before
   * record eviction so an expired pairing is reported as such.
   */
  openClaim(input: { pairId: string; proof: string; nowMs: number }): ClaimResult {
    const key = pairHash(input.pairId);
    const record = this.records.get(key);
    if (!record) return { ok: false, reason: "unknown" };
    if (record.status === "revoked") return { ok: false, reason: "revoked" };
    if (input.nowMs >= record.expiresAtMs) {
      this.records.delete(key);
      this.states.delete(record.oauthStateHash);
      this.dropNoncesFor(key);
      return { ok: false, reason: "expired" };
    }
    if (record.status !== "authorized") return { ok: false, reason: "not_authorized_yet" };
    if (!this.verifyProof(record, input.proof)) return { ok: false, reason: "invalid_proof" };
    record.status = "enrolled";
    return {
      ok: true,
      deviceSigningPublicKeyPem: record.deviceSigningPublicKeyPem,
      deviceEncryptionPublicKeyPem: record.deviceEncryptionPublicKeyPem
    };
  }

  /** Boolean facade over openClaim, kept for callers that only need success/failure. */
  claim(input: { pairId: string; proof: string; nowMs: number }): boolean {
    return this.openClaim(input).ok;
  }

  /**
   * Issues a single-use nonce bound to an enrolled pairing. Unknown or revoked
   * pairings fail closed and never receive a nonce.
   */
  issueNonce(input: { pairId: string; nowMs: number; ttlMs: number }): IssueNonceResult {
    if (!Number.isInteger(input.ttlMs) || input.ttlMs < 1 || input.ttlMs > MAX_NONCE_TTL_MS) {
      throw new Error("Nonce TTL must be at most 120s");
    }
    this.evictExpiredNonces(input.nowMs);
    const key = pairHash(input.pairId);
    const record = this.records.get(key);
    if (!record) return { ok: false, reason: "unknown" };
    if (record.status === "revoked") return { ok: false, reason: "revoked" };
    if (record.status !== "enrolled") return { ok: false, reason: "not_authorized_yet" };
    const nonce = encode(this.random(32));
    const expiresAtMs = input.nowMs + input.ttlMs;
    this.nonces.set(stateHash(nonce), { pairKeyHash: key, expiresAtMs });
    return { ok: true, nonce, expiresAtMs };
  }

  /**
   * Consumes a nonce atomically (deleted before signature verification, so a
   * replay always fails) and verifies an Ed25519 signature over the nonce bytes
   * against the enrolled device key.
   */
  consumeNonce(input: { pairId: string; nonce: string; proof: string; nowMs: number }): ConsumeNonceResult {
    this.evictExpiredNonces(input.nowMs);
    const key = pairHash(input.pairId);
    const record = this.records.get(key);
    if (!record) return { ok: false, reason: "unknown" };
    if (record.status === "revoked") return { ok: false, reason: "revoked" };
    if (input.nowMs >= record.expiresAtMs) return { ok: false, reason: "expired" };
    if (record.status !== "enrolled") return { ok: false, reason: "not_authorized_yet" };

    const nonceHash = stateHash(input.nonce);
    const pending = this.nonces.get(nonceHash);
    if (!pending || pending.pairKeyHash !== key) return { ok: false, reason: "invalid_nonce" };
    this.nonces.delete(nonceHash);
    if (input.nowMs >= pending.expiresAtMs) return { ok: false, reason: "invalid_nonce" };

    const nonceBytes = Buffer.from(input.nonce, "base64url");
    if (!this.verifyProof(record, input.proof, nonceBytes)) return { ok: false, reason: "invalid_proof" };
    return { ok: true, deviceEncryptionPublicKeyPem: record.deviceEncryptionPublicKeyPem };
  }

  /**
   * Operator revocation: marks the pairing permanently unusable and drops the
   * one-time OAuth state/handle entries and any outstanding nonces. Returns
   * false for an unknown pairId so the admin surface can report it without
   * leaking record internals.
   */
  revoke(input: { pairId: string; nowMs: number }): boolean {
    const key = pairHash(input.pairId);
    const record = this.records.get(key);
    if (!record) return false;
    record.status = "revoked";
    this.states.delete(record.oauthStateHash);
    if (record.callbackHandleHash) this.callbackHandles.delete(record.callbackHandleHash);
    record.callbackHandleHash = undefined;
    this.dropNoncesFor(key);
    return true;
  }

  /** Verifies an Ed25519 proof; message defaults to the pairing proof message. */
  private verifyProof(record: RecordState, proof: string, message?: Buffer): boolean {
    const payload = message ?? Buffer.from(record.proofMessage);
    let bytes: Buffer;
    try {
      bytes = Buffer.from(proof, "base64url");
    } catch {
      return false;
    }
    if (!bytes.length) return false;
    return verify(null, payload, record.devicePublicKey, bytes);
  }

  /** Non-secret handshake phase for a pairId, or undefined when this process never saw it. */
  statusOf(pairId: string): PairingStatus | undefined {
    return this.records.get(pairHash(pairId))?.status;
  }

  /** Test-safe introspection: no pair ID, device key or credential value is exposed. */
  debugRecord(pairId: string): { hasPlainPairId: false; status: Status } | undefined {
    const record = this.records.get(pairHash(pairId));
    return record ? { hasPlainPairId: false, status: record.status } : undefined;
  }

  /** Test-only count after expiry eviction; values remain non-sensitive. */
  debugSize(): number { return this.records.size; }
}
