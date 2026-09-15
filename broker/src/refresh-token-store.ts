import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { chmod, open, readFile, rename, rm } from "node:fs/promises";
import { basename, dirname, join } from "node:path";
import { ProtectedDirectoryError, ensureProtectedDirectory } from "./protected-directory.js";

/**
 * Protected storage for the single broker-held Google refresh token.
 *
 * Threat model: the long-lived refresh token must never appear as plaintext on
 * disk, never be derivable from the OAuth client secret and never be exposed by
 * log lines or error messages. The record is therefore sealed with AES-256-GCM
 * under a separately injected 32-byte key kept outside this component.
 *
 * Record framing ("versioned" so a future format change fails closed):
 *
 *   magic(4) = "MBRT" | version(1) = 0x01 | nonce(12) | authTag(16) | ciphertext
 *
 * The magic and version bytes are bound into the ciphertext as additional
 * authenticated data, so a rewritten header cannot be silently accepted; the
 * version byte is still checked before decryption to report a typed
 * "unknown_version" failure instead of a generic integrity failure.
 */

export interface StoredRefreshToken {
  refreshToken: string;
  scope: string;
  obtainedAtMs: number;
}

export interface RefreshTokenStore {
  read(): Promise<StoredRefreshToken | undefined>;
  replace(input: { refreshToken: string; scope: string; obtainedAtMs: number }): Promise<void>;
  clear(): Promise<void>;
}

export type RefreshTokenStoreErrorCode =
  | "invalid_key"
  | "invalid_input"
  | "unknown_version"
  | "corrupt"
  | "insecure_directory"
  | "io_error";

/** Typed failure. Messages are fixed strings and never carry record material. */
export class RefreshTokenStoreError extends Error {
  readonly code: RefreshTokenStoreErrorCode;

  constructor(code: RefreshTokenStoreErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RefreshTokenStoreError";
    this.code = code;
  }
}

const MAGIC = Buffer.from("MBRT", "ascii");
const MAGIC_BYTES = MAGIC.length;
const FORMAT_VERSION = 0x01;
const VERSION_OFFSET = MAGIC_BYTES;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const NONCE_OFFSET = VERSION_OFFSET + 1;
const TAG_OFFSET = NONCE_OFFSET + NONCE_BYTES;
const HEADER_BYTES = TAG_OFFSET + TAG_BYTES;
const KEY_BYTES = 32;
const FILE_MODE = 0o600;
const AUTHENTICATED_HEADER = Buffer.concat([MAGIC, Buffer.from([FORMAT_VERSION])]);

const invalidKey = (): RefreshTokenStoreError =>
  new RefreshTokenStoreError("invalid_key", "Refresh token store key must be a 32-byte Buffer");

/**
 * Derives the refresh-token-store key from the operator-injected master 32-byte
 * key. The info string is distinct from the enrollment store's, so the two
 * encrypted stores never share a key even when wired from one master key.
 */
export function deriveRefreshTokenStoreKey(masterKey: Buffer): Buffer {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== KEY_BYTES) throw invalidKey();
  const derived = Buffer.from(
    hkdfSync("sha256", masterKey, Buffer.alloc(0), Buffer.from("gdrive-stream-refresh-token-v1", "ascii"), KEY_BYTES)
  );
  if (derived.length !== KEY_BYTES) throw invalidKey();
  return derived;
}

const corrupt = (): RefreshTokenStoreError =>
  new RefreshTokenStoreError("corrupt", "Refresh token record failed integrity verification");

function isMissingFile(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function assertRecord(input: {
  refreshToken: string;
  scope: string;
  obtainedAtMs: number;
}): StoredRefreshToken {
  if (typeof input.refreshToken !== "string" || input.refreshToken.length === 0) {
    throw new RefreshTokenStoreError("invalid_input", "Refresh token value is required");
  }
  if (typeof input.scope !== "string" || input.scope.length === 0) {
    throw new RefreshTokenStoreError("invalid_input", "Refresh token scope is required");
  }
  if (!Number.isInteger(input.obtainedAtMs) || input.obtainedAtMs < 0) {
    throw new RefreshTokenStoreError("invalid_input", "Refresh token obtainedAtMs is required");
  }
  return { refreshToken: input.refreshToken, scope: input.scope, obtainedAtMs: input.obtainedAtMs };
}

/** Parses the decrypted payload strictly: an incomplete record is a failure, never a partial result. */
function parseStoredToken(plaintext: string): StoredRefreshToken {
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw corrupt();
  }
  if (typeof parsed !== "object" || parsed === null) throw corrupt();
  const candidate = parsed as Record<string, unknown>;
  if (
    typeof candidate.refreshToken !== "string" ||
    candidate.refreshToken.length === 0 ||
    typeof candidate.scope !== "string" ||
    candidate.scope.length === 0 ||
    !Number.isInteger(candidate.obtainedAtMs) ||
    (candidate.obtainedAtMs as number) < 0
  ) {
    throw corrupt();
  }
  return {
    refreshToken: candidate.refreshToken,
    scope: candidate.scope,
    obtainedAtMs: candidate.obtainedAtMs as number
  };
}

export class EncryptedRefreshTokenStore implements RefreshTokenStore {
  private readonly filePath: string;
  private readonly key: Buffer;

  constructor(filePath: string, key: Buffer) {
    if (typeof filePath !== "string" || filePath.length === 0) {
      throw new RefreshTokenStoreError("invalid_input", "Refresh token store requires a file path");
    }
    if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) throw invalidKey();
    this.filePath = filePath;
    // Defensive copy: the caller keeps no handle that could mutate the live key.
    this.key = Buffer.from(key);
  }

  async read(): Promise<StoredRefreshToken | undefined> {
    // A relocated or foreign-owned directory fails closed before any read, so a
    // record cannot be exfiltrated through a path the service does not own.
    await this.assertProtectedDirectory(false);
    let raw: Buffer;
    try {
      raw = await readFile(this.filePath);
    } catch (error) {
      if (isMissingFile(error)) return undefined;
      throw new RefreshTokenStoreError("io_error", "Refresh token record could not be read", { cause: error });
    }

    if (raw.length < HEADER_BYTES) throw corrupt();
    if (!raw.subarray(0, MAGIC_BYTES).equals(MAGIC)) throw corrupt();
    if (raw[VERSION_OFFSET] !== FORMAT_VERSION) {
      throw new RefreshTokenStoreError(
        "unknown_version",
        "Refresh token record version is not supported"
      );
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

    return parseStoredToken(plaintext);
  }

  async replace(input: { refreshToken: string; scope: string; obtainedAtMs: number }): Promise<void> {
    const record = assertRecord(input);
    const nonce = randomBytes(NONCE_BYTES);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(AUTHENTICATED_HEADER);
    const sealed = Buffer.concat([cipher.update(JSON.stringify(record), "utf8"), cipher.final()]);
    const bytes = Buffer.concat([
      AUTHENTICATED_HEADER,
      nonce,
      cipher.getAuthTag(),
      sealed
    ]);

    await this.writeRecord(bytes);
  }

  /** Removes the stored record. Idempotent, and safe when nothing is stored. */
  async clear(): Promise<void> {
    try {
      await rm(this.filePath, { force: true });
    } catch (error) {
      throw new RefreshTokenStoreError("io_error", "Refresh token record could not be removed", { cause: error });
    }
  }

  private async assertProtectedDirectory(create: boolean): Promise<void> {
    try {
      await ensureProtectedDirectory(dirname(this.filePath), { create });
    } catch (error) {
      if (error instanceof ProtectedDirectoryError) {
        throw new RefreshTokenStoreError(
          "insecure_directory",
          "Refresh token store directory is not protected",
          { cause: error }
        );
      }
      throw error;
    }
  }

  private async writeRecord(bytes: Buffer): Promise<void> {
    const directory = dirname(this.filePath);
    const temporaryPath = join(
      directory,
      `.${basename(this.filePath)}.${randomBytes(8).toString("hex")}.tmp`
    );

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
      if (error instanceof RefreshTokenStoreError) throw error;
      throw new RefreshTokenStoreError("io_error", "Refresh token record could not be written", { cause: error });
    }
  }
}
