import {
  createCipheriv,
  createDecipheriv,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  type KeyObject
} from "node:crypto";

/**
 * Device-bound sealed lease.
 *
 * A short-lived read-only access token is sealed to the mobile device's X25519
 * public key so it never travels in cleartext and never lands in a log or file.
 *
 * Scheme (node:crypto only):
 *   - ephemeral X25519 keypair per sealing, ECDH against the device key;
 *   - HKDF-SHA256 with a random 32-byte salt and info "gdrive-stream-lease-v1";
 *   - ChaCha20-Poly1305 with a random 12-byte nonce and AAD "gdrive-stream-lease-v1".
 *
 * Envelope: { v: 1, epk, salt, nonce, ct } — every field base64url, where epk is
 * the raw 32-byte ephemeral X25519 public key and ct = ciphertext || tag.
 */

const HKDF_INFO = Buffer.from("gdrive-stream-lease-v1", "ascii");
const AAD = Buffer.from("gdrive-stream-lease-v1", "ascii");
const SALT_BYTES = 32;
const NONCE_BYTES = 12;
const KEY_BYTES = 32;
const TAG_BYTES = 16;
const X25519_RAW_BYTES = 32;
// DER prefix for an X25519 SubjectPublicKeyInfo; the trailing 32 bytes are the key.
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export interface SealedLease {
  v: 1;
  epk: string;
  salt: string;
  nonce: string;
  ct: string;
}

export type LeaseSealerErrorCode = "invalid_key" | "invalid_envelope" | "corrupt";

export class LeaseSealerError extends Error {
  readonly code: LeaseSealerErrorCode;

  constructor(code: LeaseSealerErrorCode, message: string) {
    super(message);
    this.name = "LeaseSealerError";
    this.code = code;
  }
}

function devicePublicKey(publicKeyPem: string): KeyObject {
  if (typeof publicKeyPem !== "string" || publicKeyPem.length === 0) {
    throw new LeaseSealerError("invalid_key", "Device encryption key must be an X25519 SPKI PEM");
  }
  let key: KeyObject;
  try {
    key = createPublicKey(publicKeyPem);
  } catch {
    throw new LeaseSealerError("invalid_key", "Device encryption key must be an X25519 SPKI PEM");
  }
  if (key.asymmetricKeyType !== "x25519") {
    throw new LeaseSealerError("invalid_key", "Device encryption key must be X25519");
  }
  return key;
}

function rawPublicKey(key: KeyObject): Buffer {
  const der = key.export({ type: "spki", format: "der" });
  return Buffer.from(der.subarray(der.length - X25519_RAW_BYTES));
}

function publicKeyFromRaw(raw: Buffer): KeyObject {
  return createPublicKey({ key: Buffer.concat([X25519_SPKI_PREFIX, raw]), format: "der", type: "spki" });
}

function deriveKey(sharedSecret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync("sha256", sharedSecret, salt, HKDF_INFO, KEY_BYTES));
}

function decode(value: unknown, expectedBytes: number): Buffer {
  if (typeof value !== "string") throw new LeaseSealerError("invalid_envelope", "Malformed sealed lease envelope");
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== expectedBytes) throw new LeaseSealerError("invalid_envelope", "Malformed sealed lease envelope");
  return bytes;
}

export function sealLease(input: {
  payload: unknown;
  deviceEncryptionPublicKeyPem: string;
  random?: (size: number) => Buffer;
}): SealedLease {
  const recipient = devicePublicKey(input.deviceEncryptionPublicKeyPem);
  const random = input.random ?? randomBytes;
  const ephemeral = generateKeyPairSync("x25519");
  const sharedSecret = diffieHellman({ privateKey: ephemeral.privateKey, publicKey: recipient });
  const salt = random(SALT_BYTES);
  const nonce = random(NONCE_BYTES);
  const key = deriveKey(sharedSecret, salt);

  const cipher = createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_BYTES });
  cipher.setAAD(AAD, { plaintextLength: Buffer.byteLength(JSON.stringify(input.payload), "utf8") });
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(JSON.stringify(input.payload), "utf8")), cipher.final()]);
  const sealed = Buffer.concat([ciphertext, cipher.getAuthTag()]);

  return {
    v: 1,
    epk: rawPublicKey(ephemeral.publicKey).toString("base64url"),
    salt: salt.toString("base64url"),
    nonce: nonce.toString("base64url"),
    ct: sealed.toString("base64url")
  };
}

/** Unseal. Used by the device and by tests; a wrong device key fails the auth tag. */
export function unsealLease(input: {
  envelope: SealedLease | string;
  deviceEncryptionPrivateKeyPem: string;
}): unknown {
  const envelope: SealedLease = typeof input.envelope === "string" ? (JSON.parse(input.envelope) as SealedLease) : input.envelope;
  if (!envelope || envelope.v !== 1) throw new LeaseSealerError("invalid_envelope", "Unsupported sealed lease envelope");

  const privateKey = createPrivateKey(input.deviceEncryptionPrivateKeyPem);
  if (privateKey.asymmetricKeyType !== "x25519") {
    throw new LeaseSealerError("invalid_key", "Device encryption key must be X25519");
  }

  const salt = decode(envelope.salt, SALT_BYTES);
  const nonce = decode(envelope.nonce, NONCE_BYTES);
  const ephemeralRaw = decode(envelope.epk, X25519_RAW_BYTES);
  if (typeof envelope.ct !== "string") throw new LeaseSealerError("invalid_envelope", "Malformed sealed lease envelope");
  const sealed = Buffer.from(envelope.ct, "base64url");
  if (sealed.length < TAG_BYTES) throw new LeaseSealerError("invalid_envelope", "Malformed sealed lease envelope");

  const sharedSecret = diffieHellman({ privateKey, publicKey: publicKeyFromRaw(ephemeralRaw) });
  const key = deriveKey(sharedSecret, salt);

  const tag = sealed.subarray(sealed.length - TAG_BYTES);
  const ciphertext = sealed.subarray(0, sealed.length - TAG_BYTES);

  try {
    const decipher = createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: TAG_BYTES });
    decipher.setAAD(AAD, { plaintextLength: ciphertext.length });
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
    return JSON.parse(plaintext);
  } catch {
    throw new LeaseSealerError("corrupt", "Sealed lease failed integrity verification");
  }
}
