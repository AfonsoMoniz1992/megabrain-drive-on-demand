import { createCipheriv, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  EncryptedRefreshTokenStore,
  RefreshTokenStoreError,
  type RefreshTokenStore
} from "../broker/src/refresh-token-store";

// On-disk framing (see broker/src/refresh-token-store.ts):
// magic(4) | version(1) | nonce(12) | authTag(16) | ciphertext
const MAGIC = Buffer.from("MBRT", "ascii");
const VERSION_OFFSET = 4;
const NONCE_OFFSET = 5;
const TAG_OFFSET = 17;
const HEADER_BYTES = 33;
const RECORD_VERSION = 1;
const AAD = Buffer.concat([MAGIC, Buffer.from([RECORD_VERSION])]);

const KEY = Buffer.alloc(32, 7);
const OTHER_KEY = Buffer.alloc(32, 9);
const TOKEN = "1//0g-refresh-token-plaintext-secret-value";
const SCOPE = "https://www.googleapis.com/auth/drive.readonly";

const directories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "mbrt-"));
  directories.push(directory);
  return directory;
}

function recordPath(directory: string = tempDirectory()): string {
  return join(directory, "protected", "refresh-token.bin");
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function store(filePath: string, key: Buffer = KEY): EncryptedRefreshTokenStore {
  return new EncryptedRefreshTokenStore(filePath, key);
}

async function captureFailure(action: () => Promise<unknown>): Promise<RefreshTokenStoreError> {
  try {
    await action();
  } catch (error) {
    return error as RefreshTokenStoreError;
  }
  throw new Error("expected the store to fail closed, but it resolved");
}

async function expectFailClosed(action: () => Promise<unknown>, code: string): Promise<void> {
  const error = await captureFailure(action);
  expect(error).toBeInstanceOf(RefreshTokenStoreError);
  expect(error.code).toBe(code);
  expect(error.message).not.toContain(TOKEN);
  expect(error.message).not.toContain(KEY.toString("base64"));
}

function tamper(filePath: string, offset: number): void {
  const raw = readFileSync(filePath);
  const index = offset < 0 ? raw.length + offset : offset;
  raw[index] ^= 0xff;
  writeFileSync(filePath, raw);
}

function reseal(filePath: string, plaintext: string): void {
  const raw = readFileSync(filePath);
  const nonce = raw.subarray(NONCE_OFFSET, NONCE_OFFSET + 12);
  const cipher = createCipheriv("aes-256-gcm", KEY, nonce);
  cipher.setAAD(AAD);
  const sealed = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  writeFileSync(
    filePath,
    Buffer.concat([MAGIC, Buffer.from([RECORD_VERSION]), nonce, cipher.getAuthTag(), sealed])
  );
}

describe("broker protected refresh-token store", () => {
  it("round-trips a stored refresh token and reports absence honestly", async () => {
    const filePath = recordPath();
    const subject: RefreshTokenStore = store(filePath);

    expect(await subject.read()).toBeUndefined();

    const obtainedAtMs = 1_756_000_000_000;
    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs });

    expect(await subject.read()).toEqual({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs });
  });

  it("replaces an existing record without leaving the previous token on disk", async () => {
    const filePath = recordPath();
    const subject = store(filePath);
    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });
    const replacement = "1//0g-a-completely-different-refresh-token";

    await subject.replace({ refreshToken: replacement, scope: SCOPE, obtainedAtMs: 1_756_000_009_000 });

    expect(await subject.read()).toEqual({
      refreshToken: replacement,
      scope: SCOPE,
      obtainedAtMs: 1_756_000_009_000
    });
    const raw = readFileSync(filePath).toString("utf8");
    expect(raw.includes(TOKEN)).toBe(false);
    expect(raw.includes(replacement)).toBe(false);
  });

  it("never persists refresh-token plaintext in the record bytes", async () => {
    const filePath = recordPath();
    await store(filePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });

    const raw = readFileSync(filePath);
    expect(raw.includes(Buffer.from(TOKEN, "utf8"))).toBe(false);
    expect(raw.toString("utf8").includes(TOKEN)).toBe(false);
    expect(raw.subarray(0, 4).toString("ascii")).toBe("MBRT");
  });

  it("fails closed when the record is opened with the wrong key", async () => {
    const filePath = recordPath();
    await store(filePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });

    await expectFailClosed(() => store(filePath, OTHER_KEY).read(), "corrupt");
  });

  it("fails closed when the ciphertext or auth tag is tampered with", async () => {
    const ciphertextPath = recordPath();
    await store(ciphertextPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    tamper(ciphertextPath, -1);
    await expectFailClosed(() => store(ciphertextPath).read(), "corrupt");

    const tagPath = recordPath();
    await store(tagPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    tamper(tagPath, TAG_OFFSET);
    await expectFailClosed(() => store(tagPath).read(), "corrupt");

    const noncePath = recordPath();
    await store(noncePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    tamper(noncePath, NONCE_OFFSET);
    await expectFailClosed(() => store(noncePath).read(), "corrupt");
  });

  it("fails closed when the record is truncated", async () => {
    const filePath = recordPath();
    await store(filePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    const raw = readFileSync(filePath);

    writeFileSync(filePath, raw.subarray(0, HEADER_BYTES - 1));
    await expectFailClosed(() => store(filePath).read(), "corrupt");

    writeFileSync(filePath, raw.subarray(0, 4));
    await expectFailClosed(() => store(filePath).read(), "corrupt");

    writeFileSync(filePath, Buffer.alloc(0));
    await expectFailClosed(() => store(filePath).read(), "corrupt");
  });

  it("fails closed on an unknown or corrupted version marker", async () => {
    const futurePath = recordPath();
    await store(futurePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    const future = readFileSync(futurePath);
    future[VERSION_OFFSET] = RECORD_VERSION + 1;
    writeFileSync(futurePath, future);
    await expectFailClosed(() => store(futurePath).read(), "unknown_version");

    const corruptPath = recordPath();
    await store(corruptPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    const corrupt = readFileSync(corruptPath);
    corrupt[VERSION_OFFSET] = 0;
    writeFileSync(corruptPath, corrupt);
    await expectFailClosed(() => store(corruptPath).read(), "unknown_version");
  });

  it("fails closed instead of returning partial data from a valid-but-incomplete payload", async () => {
    const missingFieldPath = recordPath();
    await store(missingFieldPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    reseal(missingFieldPath, JSON.stringify({ scope: SCOPE }));
    await expectFailClosed(() => store(missingFieldPath).read(), "corrupt");

    const wrongTypesPath = recordPath();
    await store(wrongTypesPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    reseal(wrongTypesPath, JSON.stringify({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: "1" }));
    await expectFailClosed(() => store(wrongTypesPath).read(), "corrupt");

    const notJsonPath = recordPath();
    await store(notJsonPath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1 });
    reseal(notJsonPath, "not-a-record");
    await expectFailClosed(() => store(notJsonPath).read(), "corrupt");
  });

  it("clears the record and stays idempotent when nothing is stored", async () => {
    const filePath = recordPath();
    const subject = store(filePath);
    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });

    await subject.clear();
    expect(await subject.read()).toBeUndefined();

    await expect(subject.clear()).resolves.toBeUndefined();
    expect(await subject.read()).toBeUndefined();

    const absent = store(recordPath());
    await expect(absent.clear()).resolves.toBeUndefined();
    expect(await absent.read()).toBeUndefined();
  });

  it("writes the record 0600 inside a directory created 0700", async () => {
    const directory = tempDirectory();
    const filePath = recordPath(directory);
    const subject = store(filePath);

    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });

    expect(statSync(join(directory, "protected")).mode & 0o777).toBe(0o700);
    expect(statSync(filePath).mode & 0o777).toBe(0o600);

    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_001_000 });
    expect(statSync(filePath).mode & 0o777).toBe(0o600);
    expect(readFileSync(filePath).length).toBeGreaterThan(HEADER_BYTES);
  });

  it("publishes the record atomically without leaving temporary files behind", async () => {
    const directory = tempDirectory();
    const filePath = recordPath(directory);
    const recordDir = join(directory, "protected");
    const subject = store(filePath);

    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });
    expect(readdirSync(recordDir)).toEqual(["refresh-token.bin"]);

    await subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_001_000 });
    expect(readdirSync(recordDir)).toEqual(["refresh-token.bin"]);

    await subject.clear();
    expect(readdirSync(recordDir)).toEqual([]);
  });

  it("tightens a pre-existing wider-than-0700 directory to 0700", async () => {
    const directory = tempDirectory();
    const protectedDir = join(directory, "protected");
    mkdirSync(protectedDir, { recursive: true });
    chmodSync(protectedDir, 0o755);
    expect(statSync(protectedDir).mode & 0o777).toBe(0o755);

    await store(recordPath(directory)).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });

    expect(statSync(protectedDir).mode & 0o777).toBe(0o700);
    expect(statSync(recordPath(directory)).mode & 0o777).toBe(0o600);
  });

  it("refuses a directory not owned by the service uid", async () => {
    const directory = tempDirectory();
    const filePath = recordPath(directory);
    const realUid = typeof process.getuid === "function" ? process.getuid() : 0;
    const uid = vi.spyOn(process, "getuid").mockReturnValue(realUid + 1);
    try {
      const writeFailure = await captureFailure(() =>
        store(filePath).replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 })
      );
      expect(writeFailure).toBeInstanceOf(RefreshTokenStoreError);
      expect(writeFailure.code).toBe("insecure_directory");
      expect(writeFailure.message).not.toContain(TOKEN);
      // Nothing was written into a directory the service does not own.
      expect(existsSync(filePath)).toBe(false);
      // Reads are refused too, so a relocated store cannot be exfiltrated.
      const readFailure = await captureFailure(() => store(filePath).read());
      expect(readFailure.code).toBe("insecure_directory");
    } finally {
      uid.mockRestore();
    }
  });

  it("rejects keys that are not exactly 32 bytes or not a Buffer", () => {
    const filePath = recordPath();
    expect(() => new EncryptedRefreshTokenStore(filePath, Buffer.alloc(31))).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, Buffer.alloc(33))).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, Buffer.alloc(0))).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, randomBytes(16))).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, "0".repeat(32) as unknown as Buffer)).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, new Uint8Array(32) as unknown as Buffer)).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, undefined as unknown as Buffer)).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore("", KEY)).toThrow(RefreshTokenStoreError);
    expect(() => new EncryptedRefreshTokenStore(filePath, KEY)).not.toThrow();
  });

  it("rejects invalid input without touching the stored record", async () => {
    const filePath = recordPath();
    const subject = store(filePath);

    await expect(
      subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 })
    ).resolves.toBeUndefined();
    const before = readFileSync(filePath);

    await expect(subject.replace({ refreshToken: "", scope: SCOPE, obtainedAtMs: 5 })).rejects.toBeInstanceOf(RefreshTokenStoreError);
    await expect(subject.replace({ refreshToken: TOKEN, scope: "", obtainedAtMs: 5 })).rejects.toBeInstanceOf(RefreshTokenStoreError);
    await expect(
      subject.replace({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1.5 })
    ).rejects.toBeInstanceOf(RefreshTokenStoreError);

    expect(readFileSync(filePath).equals(before)).toBe(true);
    expect(await subject.read()).toEqual({ refreshToken: TOKEN, scope: SCOPE, obtainedAtMs: 1_756_000_000_000 });
  });

  it("exposes only read, replace and clear", () => {
    const subject = store(recordPath()) as unknown as Record<string, unknown>;
    for (const method of ["read", "replace", "clear"]) expect(typeof subject[method]).toBe("function");
    for (const forbidden of ["list", "readAll", "entries", "values", "getAll", "refreshToken"]) {
      expect(subject[forbidden]).toBeUndefined();
    }
  });
});
