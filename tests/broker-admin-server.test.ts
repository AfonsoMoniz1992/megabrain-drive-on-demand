import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { createAdminServer } from "../broker/src/admin-server";
import { deviceSigningKeyFingerprint, EnrollmentStore } from "../broker/src/enrollment-store";
import { InMemoryEnrollmentRecordStore } from "../broker/src/enrollment-record-store";
import { PairingStore } from "../broker/src/pairing-store";
import { EncryptedRefreshTokenStore } from "../broker/src/refresh-token-store";

const ADMIN_TOKEN = "operator-admin-token-must-not-be-logged";
const REFRESH_TOKEN = "1//0g-refresh-token-must-not-appear";
const SCOPE = "https://www.googleapis.com/auth/drive.readonly";

type AdminServer = ReturnType<typeof createAdminServer>;

const servers: AdminServer[] = [];
const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function ed25519PublicKeyPem(): string {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function x25519PublicKeyPem(): string {
  return generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

/** Operator-approved fingerprint of a freshly generated device signing key. */
function deviceFingerprint(): string {
  return deviceSigningKeyFingerprint(
    generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString()
  );
}

interface Harness {
  baseUrl: string;
  enrollmentStore: EnrollmentStore;
  enrollmentRecordStore: InMemoryEnrollmentRecordStore;
  pairingStore: PairingStore;
  refreshTokenStore: EncryptedRefreshTokenStore;
}

async function startHarness(nowMs = 1_000): Promise<Harness> {
  const directory = mkdtempSync(join(tmpdir(), "mbrt-admin-"));
  directories.push(directory);
  const enrollmentStore = new EnrollmentStore();
  const enrollmentRecordStore = new InMemoryEnrollmentRecordStore();
  const pairingStore = new PairingStore();
  const refreshTokenStore = new EncryptedRefreshTokenStore(join(directory, "protected", "refresh-token.bin"), Buffer.alloc(32, 7));
  const server = createAdminServer({
    adminToken: ADMIN_TOKEN,
    enrollmentStore,
    enrollmentRecordStore,
    pairingStore,
    refreshTokenStore,
    now: () => nowMs
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test admin server address missing");
  return { baseUrl: `http://127.0.0.1:${address.port}`, enrollmentStore, enrollmentRecordStore, pairingStore, refreshTokenStore };
}

function authorized(pairingStore: PairingStore): string {
  const created = pairingStore.create({
    devicePublicKeyPem: ed25519PublicKeyPem(),
    deviceEncryptionPublicKeyPem: x25519PublicKeyPem(),
    nowMs: 1_000,
    ttlMs: 300_000
  } as never);
  const callback = pairingStore.consumeOAuthState({ oauthState: created.oauthState, nowMs: 2_000 });
  if (!callback) throw new Error("callback state was not consumed");
  expect(pairingStore.markAuthorized({ callbackHandle: callback.callbackHandle, nowMs: 2_000 })).toBe(true);
  return created.pairId;
}

function mintRequest(harness: Harness, body: unknown): Promise<Response> {
  return fetch(`${harness.baseUrl}/admin/enrollment`, {
    method: "POST",
    headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}

describe("broker admin surface", () => {
  it("requires the admin bearer token and performs no side effects without it", async () => {
    const harness = await startHarness();

    expect((await fetch(`${harness.baseUrl}/admin/enrollment`, { method: "POST" })).status).toBe(401);
    expect((await fetch(`${harness.baseUrl}/admin/enrollment`)).status).toBe(401);
    expect((await fetch(`${harness.baseUrl}/admin/revoke`, { method: "POST" })).status).toBe(401);
    expect(
      (
        await fetch(`${harness.baseUrl}/admin/enrollment`, {
          method: "POST",
          headers: { authorization: "Bearer wrong-token" }
        })
      ).status
    ).toBe(401);

    // Fail-closed: no code was minted by any rejected request.
    const metadata = await fetch(`${harness.baseUrl}/admin/enrollment`, {
      headers: { authorization: `Bearer ${ADMIN_TOKEN}` }
    });
    expect(metadata.status).toBe(200);
    expect(await metadata.json()).toMatchObject({ count: 0, used: 0, unused: 0 });
  });

  it("mints a single-use code exactly once and never exposes it again", async () => {
    const harness = await startHarness();
    const minted = await mintRequest(harness, { deviceFingerprint: deviceFingerprint() });
    expect(minted.status).toBe(201);
    const body = (await minted.json()) as { code: string; expiresAtMs: number };
    expect(body.code).toMatch(/^[0-9A-Z]{4}(-[0-9A-Z]{4}){1,}$/);
    expect(body.expiresAtMs).toBeGreaterThan(1_000);

    const metadata = (await (
      await fetch(`${harness.baseUrl}/admin/enrollment`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })
    ).json()) as Record<string, unknown>;
    expect(metadata).toEqual({ count: 1, used: 0, unused: 1, expiries: [body.expiresAtMs] });
    expect(JSON.stringify(metadata)).not.toContain(body.code);
  });

  it("refuses to mint a code without the operator-approved device fingerprint", async () => {
    const harness = await startHarness();

    // No body / no JSON content type, an empty value, a malformed value and a
    // non-string value are all refused without minting anything.
    expect((await fetch(`${harness.baseUrl}/admin/enrollment`, { method: "POST", headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })).status).toBe(415);
    for (const deviceFingerprintValue of ["", "not-a-fingerprint", "a".repeat(63), "z".repeat(64), 42, null, undefined]) {
      expect((await mintRequest(harness, { deviceFingerprint: deviceFingerprintValue })).status).toBe(400);
    }

    const metadata = (await (
      await fetch(`${harness.baseUrl}/admin/enrollment`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } })
    ).json()) as Record<string, unknown>;
    expect(metadata).toMatchObject({ count: 0, used: 0, unused: 0 });
  });

  it("pre-binds the minted code to the approved device fingerprint", async () => {
    const harness = await startHarness();
    const approved = deviceFingerprint();
    const other = deviceFingerprint();

    const minted = await mintRequest(harness, { deviceFingerprint: approved });
    expect(minted.status).toBe(201);
    const { code } = (await minted.json()) as { code: string };

    // Only the approved device fingerprint can redeem the code, and only once.
    expect(harness.enrollmentStore.consume({ code, nowMs: 2_000, deviceFingerprint: other })).toEqual({
      ok: false,
      reason: "fingerprint_mismatch"
    });
    expect(harness.enrollmentStore.consume({ code, nowMs: 2_001, deviceFingerprint: approved })).toEqual({ ok: true });
    expect(harness.enrollmentStore.consume({ code, nowMs: 2_002, deviceFingerprint: approved })).toEqual({
      ok: false,
      reason: "used"
    });
  });

  it("accepts an upper-case fingerprint and matches it case-insensitively", async () => {
    const harness = await startHarness();
    const approved = deviceFingerprint();

    const minted = await mintRequest(harness, { deviceFingerprint: approved.toUpperCase() });
    expect(minted.status).toBe(201);
    const { code } = (await minted.json()) as { code: string };

    expect(harness.enrollmentStore.consume({ code, nowMs: 2_000, deviceFingerprint: approved })).toEqual({ ok: true });
  });

  it("revokes a pairing by pairId and clears the stored refresh token", async () => {
    const harness = await startHarness();
    const pairId = authorized(harness.pairingStore);
    await harness.refreshTokenStore.replace({ refreshToken: REFRESH_TOKEN, scope: SCOPE, obtainedAtMs: 1_000 });

    const response = await fetch(`${harness.baseUrl}/admin/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ pairId })
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ revoked: true });
    expect(harness.pairingStore.debugRecord(pairId)).toEqual({ hasPlainPairId: false, status: "revoked" });
    expect(await harness.refreshTokenStore.read()).toBeUndefined();
  });

  it("does not revoke an unknown pairing", async () => {
    const harness = await startHarness();
    const response = await fetch(`${harness.baseUrl}/admin/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ pairId: "0".repeat(64) })
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ revoked: false });
  });

  it("revokes the durable enrollment record so a restarted broker refuses the device", async () => {
    const harness = await startHarness();
    const pairId = "a".repeat(64);
    // Enrolled durably, but this process no longer holds the pairing handshake.
    await harness.enrollmentRecordStore.record({
      pairId,
      deviceSigningPublicKeyPem: ed25519PublicKeyPem(),
      deviceEncryptionPublicKeyPem: x25519PublicKeyPem(),
      enrolledAtMs: 1_000,
      expiresAtMs: 1_000 + 90 * 24 * 60 * 60_000
    });

    const response = await fetch(`${harness.baseUrl}/admin/revoke`, {
      method: "POST",
      headers: { authorization: `Bearer ${ADMIN_TOKEN}`, "content-type": "application/json" },
      body: JSON.stringify({ pairId })
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ revoked: true });
    expect(await harness.enrollmentRecordStore.find(pairId)).toMatchObject({ revoked: true });
  });

  it("never logs the admin token or enrollment code", async () => {
    const captured: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        captured.push(args.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" "));
      });
    }

    const harness = await startHarness();
    const minted = await mintRequest(harness, { deviceFingerprint: deviceFingerprint() });
    const { code } = (await minted.json()) as { code: string };
    await fetch(`${harness.baseUrl}/admin/enrollment`, { headers: { authorization: `Bearer ${ADMIN_TOKEN}` } });

    const output = captured.join("\n");
    expect(output).not.toContain(ADMIN_TOKEN);
    expect(output).not.toContain(code);
  });
});
