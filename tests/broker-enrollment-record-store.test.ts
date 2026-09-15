import { createCipheriv, generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  deriveEnrollmentStoreKey,
  EncryptedEnrollmentRecordStore,
  EnrollmentRecordStoreError,
  InMemoryEnrollmentRecordStore,
  pairIdHash
} from "../broker/src/enrollment-record-store";
import { deriveRefreshTokenStoreKey } from "../broker/src/refresh-token-store";

// On-disk framing: magic(4) = "MBEN" | version(1) = 0x01 | nonce(12) | authTag(16) | ciphertext
const MAGIC = Buffer.from("MBEN", "ascii");
const VERSION_OFFSET = 4;
const NONCE_OFFSET = 5;
const HEADER_BYTES = 33;
const RECORD_VERSION = 1;
const AAD = Buffer.concat([MAGIC, Buffer.from([RECORD_VERSION])]);

const MASTER_KEY = Buffer.alloc(32, 7);
const OTHER_MASTER_KEY = Buffer.alloc(32, 9);

const directories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "mben-"));
  directories.push(directory);
  return directory;
}

function recordPath(directory: string): string {
  return join(directory, "protected", "enrollments.bin");
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function ed25519PublicKeyPem(): string {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function x25519PublicKeyPem(): string {
  return generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function store(filePath: string, masterKey: Buffer = MASTER_KEY): EncryptedEnrollmentRecordStore {
  return new EncryptedEnrollmentRecordStore(filePath, deriveEnrollmentStoreKey(masterKey));
}

function enrollment(pairId: string) {
  return {
    pairId,
    deviceSigningPublicKeyPem: ed25519PublicKeyPem(),
    deviceEncryptionPublicKeyPem: x25519PublicKeyPem(),
    enrolledAtMs: 1_000,
    expiresAtMs: 1_000 + 90 * 24 * 60 * 60 * 1_000
  };
}

async function captureFailure(action: () => Promise<unknown>): Promise<EnrollmentRecordStoreError> {
  try {
    await action();
  } catch (error) {
    return error as EnrollmentRecordStoreError;
  }
  throw new Error("expected the store to fail closed, but it resolved");
}

describe("durable encrypted device-enrollment store", () => {
  it("derives a key distinct from the refresh-token store key", () => {
    const enrollmentKey = deriveEnrollmentStoreKey(MASTER_KEY);
    expect(enrollmentKey).toHaveLength(32);
    expect(enrollmentKey.equals(deriveRefreshTokenStoreKey(MASTER_KEY))).toBe(false);
  });

  it("rejects a master key that is not exactly 32 bytes", () => {
    for (const key of [Buffer.alloc(31), Buffer.alloc(33), Buffer.alloc(0), "0".repeat(32) as unknown as Buffer]) {
      expect(() => deriveEnrollmentStoreKey(key)).toThrow(EnrollmentRecordStoreError);
    }
  });

  it("records an enrolled device and looks it up by pairId", async () => {
    const subject = store(recordPath(tempDirectory()));
    const input = enrollment("a".repeat(64));

    expect(await subject.find(input.pairId)).toBeUndefined();
    await subject.record(input);

    expect(await subject.find(input.pairId)).toEqual({
      pairIdHash: pairIdHash(input.pairId),
      deviceSigningPublicKeyPem: input.deviceSigningPublicKeyPem,
      deviceEncryptionPublicKeyPem: input.deviceEncryptionPublicKeyPem,
      enrolledAtMs: input.enrolledAtMs,
      expiresAtMs: input.expiresAtMs,
      revoked: false
    });
    expect(await subject.find("b".repeat(64))).toBeUndefined();
    expect(await subject.count()).toBe(1);
  });

  it("persists enrolled devices across store instances (broker restart)", async () => {
    const filePath = recordPath(tempDirectory());
    const first = enrollment("c".repeat(64));
    const second = enrollment("d".repeat(64));
    await store(filePath).record(first);
    await store(filePath).record(second);

    const reopened = store(filePath);
    expect(await reopened.count()).toBe(2);
    expect(await reopened.find(first.pairId)).toMatchObject({ pairIdHash: pairIdHash(first.pairId) });
    expect(await reopened.find(second.pairId)).toMatchObject({ pairIdHash: pairIdHash(second.pairId) });
  });

  it("never persists the device public keys or pairId in the record bytes", async () => {
    const filePath = recordPath(tempDirectory());
    const pairId = "e".repeat(64);
    const input = enrollment(pairId);
    await store(filePath).record(input);

    const raw = readFileSync(filePath);
    expect(raw.subarray(0, 4).toString("ascii")).toBe("MBEN");
    expect(raw.includes(Buffer.from(input.deviceSigningPublicKeyPem, "utf8"))).toBe(false);
    expect(raw.includes(Buffer.from(input.deviceEncryptionPublicKeyPem, "utf8"))).toBe(false);
    expect(raw.includes(Buffer.from(pairId, "utf8"))).toBe(false);
  });

  it("fails closed when opened with a key derived from a different master key", async () => {
    const filePath = recordPath(tempDirectory());
    await store(filePath).record(enrollment("f".repeat(64)));

    const failure = await captureFailure(() => store(filePath, OTHER_MASTER_KEY).find("f".repeat(64)));
    expect(failure).toBeInstanceOf(EnrollmentRecordStoreError);
    expect(failure.code).toBe("corrupt");
  });

  it("fails closed on a tampered or truncated record", async () => {
    const filePath = recordPath(tempDirectory());
    await store(filePath).record(enrollment("a".repeat(64)));

    const tampered = readFileSync(filePath);
    tampered[tampered.length - 1] ^= 0xff;
    writeFileSync(filePath, tampered);
    expect((await captureFailure(() => store(filePath).count())).code).toBe("corrupt");

    const truncated = readFileSync(filePath).subarray(0, HEADER_BYTES - 1);
    writeFileSync(filePath, truncated);
    expect((await captureFailure(() => store(filePath).count())).code).toBe("corrupt");
  });

  it("fails closed on an unknown version marker", async () => {
    const filePath = recordPath(tempDirectory());
    await store(filePath).record(enrollment("a".repeat(64)));

    const future = readFileSync(filePath);
    future[VERSION_OFFSET] = RECORD_VERSION + 1;
    writeFileSync(filePath, future);
    expect((await captureFailure(() => store(filePath).count())).code).toBe("unknown_version");
  });

  it("fails closed instead of returning partial data from a resealed incomplete payload", async () => {
    const filePath = recordPath(tempDirectory());
    await store(filePath).record(enrollment("a".repeat(64)));

    const reseal = (plaintext: string) => {
      const raw = readFileSync(filePath);
      const nonce = raw.subarray(NONCE_OFFSET, NONCE_OFFSET + 12);
      const cipher = createCipheriv("aes-256-gcm", deriveEnrollmentStoreKey(MASTER_KEY), nonce);
      cipher.setAAD(AAD);
      const sealed = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
      writeFileSync(filePath, Buffer.concat([MAGIC, Buffer.from([RECORD_VERSION]), nonce, cipher.getAuthTag(), sealed]));
    };

    reseal(JSON.stringify({ records: [{ pairIdHash: "a".repeat(64) }] }));
    expect((await captureFailure(() => store(filePath).count())).code).toBe("corrupt");

    reseal("not-a-record");
    expect((await captureFailure(() => store(filePath).count())).code).toBe("corrupt");

    reseal(JSON.stringify({ records: [] }));
    expect(await store(filePath).count()).toBe(0);
  });

  it("revokes an enrolled device durably and refuses to revoke an unknown pairId", async () => {
    const filePath = recordPath(tempDirectory());
    const input = enrollment("a".repeat(64));
    await store(filePath).record(input);

    expect(await store(filePath).revoke("b".repeat(64))).toBe(false);
    expect(await store(filePath).revoke(input.pairId)).toBe(true);
    expect(await store(filePath).find(input.pairId)).toMatchObject({ revoked: true });

    // Revocation survives a restart.
    expect(await store(filePath).find(input.pairId)).toMatchObject({ revoked: true });
  });

  it("writes the record 0600 inside a directory created 0700 and publishes atomically", async () => {
    const directory = tempDirectory();
    const filePath = recordPath(directory);
    await store(filePath).record(enrollment("a".repeat(64)));

    expect(statSync(join(directory, "protected")).mode & 0o777).toBe(0o700);
    expect(statSync(filePath).mode & 0o777).toBe(0o600);
    expect(readFileSync(filePath).length).toBeGreaterThan(HEADER_BYTES);
  });

  it("tightens a pre-existing wider-than-0700 directory to 0700", async () => {
    const directory = tempDirectory();
    const protectedDir = join(directory, "protected");
    mkdirSync(protectedDir, { recursive: true });
    chmodSync(protectedDir, 0o755);
    expect(statSync(protectedDir).mode & 0o777).toBe(0o755);

    await store(recordPath(directory)).record(enrollment("a".repeat(64)));

    expect(statSync(protectedDir).mode & 0o777).toBe(0o700);
    expect(statSync(recordPath(directory)).mode & 0o777).toBe(0o600);
  });

  it("refuses a directory not owned by the service uid", async () => {
    const directory = tempDirectory();
    const filePath = recordPath(directory);
    const realUid = typeof process.getuid === "function" ? process.getuid() : 0;
    const uid = vi.spyOn(process, "getuid").mockReturnValue(realUid + 1);
    try {
      const writeFailure = await captureFailure(() => store(filePath).record(enrollment("a".repeat(64))));
      expect(writeFailure).toBeInstanceOf(EnrollmentRecordStoreError);
      expect(writeFailure.code).toBe("insecure_directory");
      expect(existsSync(filePath)).toBe(false);
      const readFailure = await captureFailure(() => store(filePath).count());
      expect(readFailure.code).toBe("insecure_directory");
    } finally {
      uid.mockRestore();
    }
  });

  it("rejects invalid enrollment input without touching the stored record", async () => {
    const filePath = recordPath(tempDirectory());
    const subject = store(filePath);
    const input = enrollment("a".repeat(64));
    await subject.record(input);
    const before = readFileSync(filePath);

    await expect(subject.record({ ...input, pairId: "" })).rejects.toBeInstanceOf(EnrollmentRecordStoreError);
    await expect(subject.record({ ...input, deviceSigningPublicKeyPem: "" })).rejects.toBeInstanceOf(EnrollmentRecordStoreError);
    await expect(subject.record({ ...input, deviceEncryptionPublicKeyPem: "not-a-key" })).rejects.toBeInstanceOf(EnrollmentRecordStoreError);
    await expect(subject.record({ ...input, enrolledAtMs: 1.5 })).rejects.toBeInstanceOf(EnrollmentRecordStoreError);
    await expect(subject.record({ ...input, expiresAtMs: 999 })).rejects.toBeInstanceOf(EnrollmentRecordStoreError);

    expect(readFileSync(filePath).equals(before)).toBe(true);
  });

  it("provides an in-memory implementation with identical lookup semantics", async () => {
    const subject = new InMemoryEnrollmentRecordStore();
    const input = enrollment("a".repeat(64));
    await subject.record(input);
    expect(await subject.find(input.pairId)).toMatchObject({ pairIdHash: pairIdHash(input.pairId), revoked: false });
    expect(await subject.revoke(input.pairId)).toBe(true);
    expect(await subject.find(input.pairId)).toMatchObject({ revoked: true });
    expect(await subject.count()).toBe(1);
  });
});
