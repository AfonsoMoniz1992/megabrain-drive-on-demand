import { createCipheriv, createDecipheriv, createHash, hkdfSync, randomBytes } from "node:crypto";
import { chmod, open, readFile, rename, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { ProtectedDirectoryError, ensureProtectedDirectory } from "./protected-directory.js";

/**
 * Durable, encrypted device-enrollment records.
 *
 * Threat model: an enrolled device must keep renewing short-lived leases long
 * after the 10-minute pairing handshake TTL has passed and across a broker
 * restart. The enrollment identity is therefore the durable authorization
 * record: the pairId hash, the device's Ed25519 signing key and X25519
 * encryption key, the enrollment time, a bounded long expiry and a revoked
 * flag. It deliberately holds no Google token material.
 *
 * At-rest protection: AES-256-GCM under a key derived with HKDF-SHA256 from the
 * operator-injected master 32-byte key using info "gdrive-stream-enrollment-v1".
 * The refresh-token store derives its key with the distinct info
 * "gdrive-stream-refresh-token-v1", so the two stores never share a key.
 *
 * Record framing (versioned so a future format change fails closed):
 *
 *   magic(4) = "MBEN" | version(1) = 0x01 | nonce(12) | authTag(16) | ciphertext
 *
 * The magic and version bytes are bound as additional authenticated data so a
 * rewritten header cannot be silently accepted; the version byte is still
 * checked before decryption to report a typed "unknown_version" failure. The
 * file is published atomically (same-directory rename) with mode 0600 inside a
 * directory created 0700.
 */

export const ENROLLMENT_STORE_HKDF_INFO = "gdrive-stream-enrollment-v1";
const KEY_BYTES = 32;

export interface EnrolledDeviceRecord {
  pairIdHash: string;
  deviceSigningPublicKeyPem: string;
  deviceEncryptionPublicKeyPem: string;
  enrolledAtMs: number;
  expiresAtMs: number;
  revoked: boolean;
}

export interface EnrollmentRecordInput {
  pairId: string;
  deviceSigningPublicKeyPem: string;
  deviceEncryptionPublicKeyPem: string;
  enrolledAtMs: number;
  expiresAtMs: number;
}

/**
 * Durable authorization boundary for enrolled devices. The pairing store owns
 * the short-lived OAuth handshake; this store owns everything that must outlive
 * it and a broker restart.
 */
export interface EnrollmentRecordStore {
  find(pairId: string): Promise<EnrolledDeviceRecord | undefined>;
  record(input: EnrollmentRecordInput): Promise<void>;
  revoke(pairId: string): Promise<boolean>;
  count(): Promise<number>;
}

export type EnrollmentRecordStoreErrorCode =
  | "invalid_key"
  | "invalid_input"
  | "unknown_version"
  | "corrupt"
  | "insecure_directory"
  | "io_error";

/** Typed failure. Messages are fixed strings and never carry record material. */
export class EnrollmentRecordStoreError extends Error {
  readonly code: EnrollmentRecordStoreErrorCode;

  constructor(code: EnrollmentRecordStoreErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "EnrollmentRecordStoreError";
    this.code = code;
  }
}

const MAGIC = Buffer.from("MBEN", "ascii");
const MAGIC_BYTES = MAGIC.length;
const FORMAT_VERSION = 0x01;
const VERSION_OFFSET = MAGIC_BYTES;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const NONCE_OFFSET = VERSION_OFFSET + 1;
const TAG_OFFSET = NONCE_OFFSET + NONCE_BYTES;
const HEADER_BYTES = TAG_OFFSET + TAG_BYTES;
const FILE_MODE = 0o600;
const AUTHENTICATED_HEADER = Buffer.concat([MAGIC, Buffer.from([FORMAT_VERSION])]);

const invalidKey = (): EnrollmentRecordStoreError =>
  new EnrollmentRecordStoreError("invalid_key", "Enrollment store key must be a 32-byte Buffer");

const corrupt = (): EnrollmentRecordStoreError =>
  new EnrollmentRecordStoreError("corrupt", "Enrollment record failed integrity verification");

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as NodeJS.ErrnoException).code === "ENOENT";
}

/** Stable, non-reversible index key for a raw pairId. */
export function pairIdHash(pairId: string): string {
  return createHash("sha256").update(pairId, "utf8").digest("hex");
}

/**
 * Derives the enrollment-store key from the injected master key. A wrong-sized
 * master key fails closed rather than silently deriving a weak key.
 */
export function deriveEnrollmentStoreKey(masterKey: Buffer): Buffer {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) throw invalidKey();
  // Defensive: the derivation output is a fresh buffer.
  const derived = Buffer.from(hkdfSync("sha256", masterKey, Buffer.alloc(0), Buffer.from(ENROLLMENT_STORE_HKDF_INFO, "ascii"), KEY_BYTES));
  if (derived.length !== KEY_BYTES) throw invalidKey();
  return derived;
}

function assertRecord(input: EnrollmentRecordInput): {
  pairIdHash: string;
  deviceSigningPublicKeyPem: string;
  deviceEncryptionPublicKeyPem: string;
  enrolledAtMs: number;
  expiresAtMs: number;
} {
  if (typeof input.pairId !== "string" || input.pairId.length === 0) {
    throw new EnrollmentRecordStoreError("invalid_input", "Enrollment requires a non-empty pairId");
  }
  if (typeof input.deviceSigningPublicKeyPem !== "string" || !input.deviceSigningPublicKeyPem.includes("PUBLIC KEY")) {
    throw new EnrollmentRecordStoreError("invalid_input", "Enrollment requires a device signing public key");
  }
  if (typeof input.deviceEncryptionPublicKeyPem !== "string" || !input.deviceEncryptionPublicKeyPem.includes("PUBLIC KEY")) {
    throw new EnrollmentRecordStoreError("invalid_input", "Enrollment requires a device encryption public key");
  }
  if (!Number.isInteger(input.enrolledAtMs) || input.enrolledAtMs < 0) {
    throw new EnrollmentRecordStoreError("invalid_input", "Enrollment requires a valid enrolledAtMs");
  }
  if (!Number.isInteger(input.expiresAtMs) || input.expiresAtMs <= input.enrolledAtMs) {
    throw new EnrollmentRecordStoreError("invalid_input", "Enrollment requires an expiry after enrolledAtMs");
  }
  return {
    pairIdHash: pairIdHash(input.pairId),
    deviceSigningPublicKeyPem: input.deviceSigningPublicKeyPem,
    deviceEncryptionPublicKeyPem: input.deviceEncryptionPublicKeyPem,
    enrolledAtMs: input.enrolledAtMs,
    expiresAtMs: input.expiresAtMs
  };
}

/** Parses the decrypted payload strictly: an incomplete record is a failure, never a partial result. */
function parseStoredRecords(plaintext: string): EnrolledDeviceRecord[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw corrupt();
  }
  if (typeof parsed !== "object" || parsed === null) throw corrupt();
  const candidate = (parsed as Record<string, unknown>).records;
  if (!Array.isArray(candidate)) throw corrupt();
  return candidate.map((entry) => {
    if (typeof entry !== "object" || entry === null) throw corrupt();
    const record = entry as Record<string, unknown>;
    if (
      typeof record.pairIdHash !== "string" ||
      !/^[0-9a-f]{64}$/.test(record.pairIdHash) ||
      typeof record.deviceSigningPublicKeyPem !== "string" ||
      record.deviceSigningPublicKeyPem.length === 0 ||
      typeof record.deviceEncryptionPublicKeyPem !== "string" ||
      record.deviceEncryptionPublicKeyPem.length === 0 ||
      !Number.isInteger(record.enrolledAtMs) ||
      (record.enrolledAtMs as number) < 0 ||
      !Number.isInteger(record.expiresAtMs) ||
      (record.expiresAtMs as number) <= 0 ||
      typeof record.revoked !== "boolean"
    ) {
      throw corrupt();
    }
    return {
      pairIdHash: record.pairIdHash,
      deviceSigningPublicKeyPem: record.deviceSigningPublicKeyPem,
      deviceEncryptionPublicKeyPem: record.deviceEncryptionPublicKeyPem,
      enrolledAtMs: record.enrolledAtMs as number,
      expiresAtMs: record.expiresAtMs as number,
      revoked: record.revoked
    };
  });
}

/** In-memory fallback with identical semantics (used by tests and OAuth-disabled wiring). */
export class InMemoryEnrollmentRecordStore implements EnrollmentRecordStore {
  private readonly records = new Map<string, EnrolledDeviceRecord>();

  async find(pairId: string): Promise<EnrolledDeviceRecord | undefined> {
    const record = this.records.get(pairIdHash(pairId));
    return record ? { ...record } : undefined;
  }

  async record(input: EnrollmentRecordInput): Promise<void> {
    const asserted = assertRecord(input);
    this.records.set(asserted.pairIdHash, { ...asserted, revoked: false });
  }

  async revoke(pairId: string): Promise<boolean> {
    const record = this.records.get(pairIdHash(pairId));
    if (!record) return false;
    record.revoked = true;
    return true;
  }

  async count(): Promise<number> {
    return this.records.size;
  }
}

export class EncryptedEnrollmentRecordStore implements EnrollmentRecordStore {
  private readonly filePath: string;
  private readonly key: Buffer;
  private readonly records = new Map<string, EnrolledDeviceRecord>();
  private loadPromise?: Promise<void>;

  constructor(filePath: string, key: Buffer) {
    if (typeof filePath !== "string" || filePath.length === 0) {
      throw new EnrollmentRecordStoreError("invalid_input", "Enrollment store requires a file path");
    }
    if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw invalidKey();
    this.filePath = filePath;
    // Defensive copy: the caller keeps no handle that could mutate the live key.
    this.key = Buffer.from(key);
  }

  private async ensureLoaded(): Promise<void> {
    // Lazy, single-flight initialisation: the file is read at most once.
    if (!this.loadPromise) this.loadPromise = this.load();
    return this.loadPromise;
  }

  private async load(): Promise<void> {
    // Fail closed before reading: a foreign-owned directory must not be able to
    // hand the service a relocated record file.
    await this.assertProtectedDirectory(false);
    let raw: Buffer;
    try {
      raw = await readFile(this.filePath);
    } catch (error) {
      if (isMissingFile(error)) return;
      throw new EnrollmentRecordStoreError("io_error", "Enrollment record could not be read", { cause: error });
    }

    if (raw.length < HEADER_BYTES) throw corrupt();
    if (!raw.subarray(0, MAGIC_BYTES).equals(MAGIC)) throw corrupt();
    if (raw[VERSION_OFFSET] !== FORMAT_VERSION) {
      throw new EnrollmentRecordStoreError("unknown_version", "Enrollment record version is not supported");
    }

    const nonce = raw.subarray(NONCE_OFFSET, NONCE_OFFSET + NONCE_BYTES);
    const authTag = raw.subarray(TAG_OFFSET, TAG_OFFSET + TAG_BYTES);
    const sealed = raw.subarray(HEADER_BYTES);
    let plaintext: string;
    try {
      const decipher = createDecipheriv("aes-256-gcm", this.key, nonce);
      decipher.setAAD(AUTHENTICATED_HEADER);
      decipher.setAuthTag(authTag);
      plaintext = Buffer.concat([decipher.update(sealed), decipher.final()]).toString("utf8");
    } catch {
      // Wrong key, tampered ciphertext/tag/nonce or truncation all land here.
      throw corrupt();
    }

    for (const record of parseStoredRecords(plaintext)) this.records.set(record.pairIdHash, record);
  }

  async find(pairId: string): Promise<EnrolledDeviceRecord | undefined> {
    await this.ensureLoaded();
    const record = this.records.get(pairIdHash(pairId));
    return record ? { ...record } : undefined;
  }

  async record(input: EnrollmentRecordInput): Promise<void> {
    const asserted = assertRecord(input);
    await this.ensureLoaded();
    this.records.set(asserted.pairIdHash, { ...asserted, revoked: false });
    await this.persist();
  }

  async revoke(pairId: string): Promise<boolean> {
    await this.ensureLoaded();
    const record = this.records.get(pairIdHash(pairId));
    if (!record) return false;
    record.revoked = true;
    await this.persist();
    return true;
  }

  async count(): Promise<number> {
    await this.ensureLoaded();
    return this.records.size;
  }

  private async assertProtectedDirectory(create: boolean): Promise<void> {
    try {
      await ensureProtectedDirectory(dirname(this.filePath), { create });
    } catch (error) {
      if (error instanceof ProtectedDirectoryError) {
        throw new EnrollmentRecordStoreError(
          "insecure_directory",
          "Enrollment record directory is not protected",
          { cause: error }
        );
      }
      throw error;
    }
  }

  private async persist(): Promise<void> {
    const payload = JSON.stringify({ records: [...this.records.values()] });
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(AUTHENTICATED_HEADER);
    const sealed = Buffer.concat([cipher.update(payload, "utf8"), cipher.final()]);
    const bytes = Buffer.concat([AUTHENTICATED_HEADER, nonce, cipher.getAuthTag(), sealed]);

    const directory = dirname(this.filePath);
    const temporaryPath = join(directory, `.${basename(this.filePath)}.${randomBytes(8).toString("hex")}.tmp`);

    try {
      await this.assertProtectedDirectory(true);
      const handle = await open(temporaryPath, "wx", FILE_MODE);
      try {
        await handle.writeFile(bytes);
        await handle.sync();
      } finally {
        await handle.close();
      }
      // Same-directory rename is the atomic publish step; the temp file already
      // carries 0600 so the published record never appears with wider access.
      await rename(temporaryPath, this.filePath);
      await chmod(this.filePath, FILE_MODE);
    } catch (error) {
      await rm(temporaryPath, { force: true }).catch(() => undefined);
      // A typed guard failure (e.g. an unprotected directory) must keep its code.
      if (error instanceof EnrollmentRecordStoreError) throw error;
      throw new EnrollmentRecordStoreError("io_error", "Enrollment record could not be written", { cause: error });
    }
  }
}
