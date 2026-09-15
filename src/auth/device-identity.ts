import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { randomBytes, utf8ToBytes } from "@noble/hashes/utils.js";

/**
 * Pure-JS device cryptography for Obsidian mobile.
 *
 * Obsidian mobile has no Node `crypto`, no hardware keystore and no secure
 * enclave access, so the device key is the only long-lived secret and it is
 * used solely to prove possession of this device to the self-hosted broker. Google
 * access material is never derived here and never persisted.
 */

/** HKDF `info` and ChaCha20-Poly1305 AAD of the sealed lease. Must not change. */
export const LEASE_INFO = "gdrive-stream-lease-v1";
/** Explicit alias so unsealing code reads symmetrically with sealing code. */
export const UNSEAL_INFO = LEASE_INFO;

const ED25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);
const X25519_SPKI_PREFIX = new Uint8Array([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00]);
const CHACHA_NONCE_BYTES = 12;
const X25519_KEY_BYTES = 32;

export interface DeviceIdentity {
  ed25519PrivateKey: Uint8Array;
  ed25519PublicKey: Uint8Array;
  x25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
}

/** Wire envelope produced by the broker: `{v:1, epk, salt, nonce, ct}`. */
export interface SealedEnvelope {
  v: number;
  epk: string;
  salt: string;
  nonce: string;
  ct: string;
}

export interface LeasePayload {
  accessToken: string;
  expiresAtMs: number;
  scope: string;
  allowedRootName: string;
}

const BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/** Base64url without padding, implemented locally so no Buffer/btoa is required. */
export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  let base64 = "";
  for (let index = 0; index < binary.length; index += 3) {
    const first = binary.charCodeAt(index);
    const second = index + 1 < binary.length ? binary.charCodeAt(index + 1) : Number.NaN;
    const third = index + 2 < binary.length ? binary.charCodeAt(index + 2) : Number.NaN;
    const triplet = (first << 16) | ((Number.isNaN(second) ? 0 : second) << 8) | (Number.isNaN(third) ? 0 : third);
    base64 += BASE64_ALPHABET[(triplet >> 18) & 63] + BASE64_ALPHABET[(triplet >> 12) & 63];
    base64 += Number.isNaN(second) ? "" : BASE64_ALPHABET[(triplet >> 6) & 63];
    base64 += Number.isNaN(third) ? "" : BASE64_ALPHABET[triplet & 63];
  }
  return base64.replace(/\+/g, "-").replace(/\//g, "_");
}

export function fromBase64Url(value: string): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) throw new Error("Value is not valid base64url");
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const bytes: number[] = [];
  let accumulator = 0;
  let bits = 0;
  for (const character of padded) {
    const index = BASE64_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("Value is not valid base64url");
    accumulator = (accumulator << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((accumulator >> bits) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function pemWrap(der: Uint8Array, label: string): string {
  // PEM requires the standard alphabet and '=' padding, unlike base64url on the wire.
  const padded = toBase64Url(der).replace(/-/g, "+").replace(/_/g, "/");
  const base64 = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  const lines: string[] = [];
  for (let index = 0; index < base64.length; index += 64) lines.push(base64.slice(index, index + 64));
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

/** Generates fresh Ed25519 (proof of possession) and X25519 (lease sealing) keys. */
export function generateDeviceIdentity(): DeviceIdentity {
  const signing = ed25519.keygen();
  const encryption = x25519.keygen();
  return {
    ed25519PrivateKey: signing.secretKey,
    ed25519PublicKey: signing.publicKey,
    x25519PrivateKey: encryption.secretKey,
    x25519PublicKey: encryption.publicKey
  };
}

/** Restores a device identity from the persisted base64url private keys. */
export function restoreDeviceIdentity(input: { ed25519PrivateKey: string; x25519PrivateKey: string }): DeviceIdentity {
  const ed25519PrivateKey = fromBase64Url(input.ed25519PrivateKey);
  const x25519PrivateKey = fromBase64Url(input.x25519PrivateKey);
  if (ed25519PrivateKey.length !== 32 || x25519PrivateKey.length !== 32) throw new Error("Stored device key is invalid");
  return {
    ed25519PrivateKey,
    ed25519PublicKey: ed25519.getPublicKey(ed25519PrivateKey),
    x25519PrivateKey,
    x25519PublicKey: x25519.getPublicKey(x25519PrivateKey)
  };
}

/** Serializes only the private keys; no broker or Google material is ever included. */
export function serializeDeviceIdentity(identity: DeviceIdentity): { ed25519PrivateKey: string; x25519PrivateKey: string } {
  return { ed25519PrivateKey: toBase64Url(identity.ed25519PrivateKey), x25519PrivateKey: toBase64Url(identity.x25519PrivateKey) };
}

export function exportEd25519SpkiPem(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return pemWrap(concatBytes(ED25519_SPKI_PREFIX, publicKey), "PUBLIC KEY");
}

export function exportX25519SpkiPem(publicKey: Uint8Array): string {
  if (publicKey.length !== X25519_KEY_BYTES) throw new Error("X25519 public key must be 32 bytes");
  return pemWrap(concatBytes(X25519_SPKI_PREFIX, publicKey), "PUBLIC KEY");
}

/** Raw X25519 public key as base64url; the broker uses it as the envelope `epk`. */
export function exportX25519RawPublicKey(identity: DeviceIdentity): string {
  return toBase64Url(identity.x25519PublicKey);
}

/** base64url Ed25519 signature over the exact message bytes. */
export function signBase64Url(identity: DeviceIdentity, message: Uint8Array): string {
  return toBase64Url(ed25519.sign(message, identity.ed25519PrivateKey));
}

export function signUtf8Base64Url(identity: DeviceIdentity, message: string): string {
  return signBase64Url(identity, utf8ToBytes(message));
}

function deriveSealKey(sharedSecret: Uint8Array, salt: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedSecret, salt, utf8ToBytes(LEASE_INFO), 32);
}

function decodeEnvelopeField(value: unknown, field: string, expectedLength?: number): Uint8Array {
  if (typeof value !== "string" || value.length === 0) throw new Error(`Lease envelope ${field} is invalid`);
  const bytes = fromBase64Url(value);
  if (expectedLength !== undefined && bytes.length !== expectedLength) throw new Error(`Lease envelope ${field} is invalid`);
  return bytes;
}

function parseLeasePayload(plaintext: Uint8Array): LeasePayload {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext));
  } catch {
    throw new Error("Lease payload is not valid JSON");
  }
  if (!parsed || typeof parsed !== "object") throw new Error("Lease payload is invalid");
  const record = parsed as Record<string, unknown>;
  if (typeof record.accessToken !== "string" || record.accessToken.length === 0) throw new Error("Lease payload has no access token");
  if (typeof record.expiresAtMs !== "number" || !Number.isFinite(record.expiresAtMs)) throw new Error("Lease payload expiry is invalid");
  if (typeof record.scope !== "string") throw new Error("Lease payload scope is invalid");
  if (typeof record.allowedRootName !== "string") throw new Error("Lease payload root is invalid");
  return { accessToken: record.accessToken, expiresAtMs: record.expiresAtMs, scope: record.scope, allowedRootName: record.allowedRootName };
}

/**
 * Unseals the broker lease: X25519 ECDH with `epk`, HKDF-SHA256 under the fixed
 * info string, then ChaCha20-Poly1305 with the fixed AAD. Failures never echo
 * ciphertext, key material or the decrypted token.
 */
export function unsealLease(identity: DeviceIdentity, envelope: SealedEnvelope): LeasePayload {
  if (!envelope || typeof envelope !== "object") throw new Error("Lease envelope is missing");
  if (envelope.v !== 1) throw new Error("Unsupported lease envelope version");
  const epk = decodeEnvelopeField(envelope.epk, "epk", X25519_KEY_BYTES);
  const salt = decodeEnvelopeField(envelope.salt, "salt");
  const nonce = decodeEnvelopeField(envelope.nonce, "nonce", CHACHA_NONCE_BYTES);
  const ciphertext = decodeEnvelopeField(envelope.ct, "ct");
  const key = deriveSealKey(x25519.getSharedSecret(identity.x25519PrivateKey, epk), salt);
  let plaintext: Uint8Array;
  try {
    plaintext = chacha20poly1305(key, nonce, utf8ToBytes(UNSEAL_INFO)).decrypt(ciphertext);
  } catch {
    throw new Error("Lease envelope could not be unsealed");
  }
  return parseLeasePayload(plaintext);
}

/**
 * Seals a lease for a recipient X25519 public key. The broker performs the same
 * operation; the plugin exports it so the unsealing path is verifiable in tests
 * without contacting the broker.
 */
export function sealLeaseEnvelope(
  recipientPublicKey: Uint8Array,
  payload: LeasePayload,
  options: { salt?: Uint8Array; nonce?: Uint8Array; ephemeralPrivateKey?: Uint8Array } = {}
): SealedEnvelope {
  if (recipientPublicKey.length !== X25519_KEY_BYTES) throw new Error("Recipient X25519 public key must be 32 bytes");
  const ephemeralPrivateKey = options.ephemeralPrivateKey ?? x25519.utils.randomSecretKey();
  const epk = x25519.getPublicKey(ephemeralPrivateKey);
  const salt = options.salt ?? randomBytes(16);
  const nonce = options.nonce ?? randomBytes(CHACHA_NONCE_BYTES);
  const key = deriveSealKey(x25519.getSharedSecret(ephemeralPrivateKey, recipientPublicKey), salt);
  const ciphertext = chacha20poly1305(key, nonce, utf8ToBytes(LEASE_INFO)).encrypt(utf8ToBytes(JSON.stringify(payload)));
  return { v: 1, epk: toBase64Url(epk), salt: toBase64Url(salt), nonce: toBase64Url(nonce), ct: toBase64Url(ciphertext) };
}

/** Canonical SHA-256 fingerprint of the Ed25519 SPKI, identical to the broker's enrollment binding. */
export function deviceFingerprint(identity: DeviceIdentity): string {
  const spkiDer = concatBytes(ED25519_SPKI_PREFIX, identity.ed25519PublicKey);
  return Array.from(sha256(spkiDer), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
