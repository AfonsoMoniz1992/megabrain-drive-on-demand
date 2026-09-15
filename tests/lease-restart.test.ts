import { describe, expect, it } from "vitest";
import { BrokerClient, type BrokerRequest, type BrokerResponse } from "../src/auth/broker-client";
import { generateDeviceIdentity, sealLeaseEnvelope, type LeasePayload } from "../src/auth/device-identity";
import { LeaseManager, type EnrollmentView } from "../src/auth/lease-manager";

const BASE_URL = "https://broker.example.test/gdrive-stream-oauth";
const PAIR_ID = "a".repeat(64);

const RESTART_PAYLOAD: LeasePayload = { accessToken: "ya29.restart", expiresAtMs: 1_600_000, scope: "drive.readonly", allowedRootName: "example-test-root" };

function restart(options: { nonceStatus?: number; leaseStatus?: number; onEnrollment?: (state: EnrollmentView) => void } = {}) {
  const identity = generateDeviceIdentity();
  const calls: string[] = [];
  const broker = new BrokerClient({
    baseUrl: BASE_URL,
    request: async (request: BrokerRequest): Promise<BrokerResponse> => {
      calls.push(request.url.replace(BASE_URL, ""));
      if (request.url.endsWith("/oauth/nonce")) {
        const status = options.nonceStatus ?? 200;
        return status === 200 ? { status, json: { nonce: "restart-nonce", expiresAtMs: 30_000 } } : { status, json: { error: "expired" } };
      }
      if (request.url.endsWith("/oauth/lease")) {
        const status = options.leaseStatus ?? 200;
        return status === 200
          ? { status, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, RESTART_PAYLOAD), expiresAtMs: 600_000 } }
          : { status, json: { error: status === 403 ? "revoked" : "expired" } };
      }
      throw new Error(`unexpected ${request.url}`);
    }
  });
  const manager = new LeaseManager({
    broker,
    identity,
    openAuthorizationUrl: () => undefined,
    now: () => 1_000_000,
    sleep: async () => undefined,
    initialPairId: PAIR_ID,
    onEnrollment: options.onEnrollment
  });
  return { manager, calls };
}

describe("restart-safe lease renewal", () => {
  it("treats a persisted pairing as enrolled so the browser resumes after a restart", () => {
    const { manager, calls } = restart();
    expect(manager.enrollment).toEqual({ pairId: PAIR_ID, status: "enrolled", expiresAtMs: null });
    expect(manager.enrolled).toBe(false);
    expect(calls).toEqual([]);
  });

  it("obtains a fresh nonce and lease after restart without re-pairing", async () => {
    const { manager, calls } = restart();
    await expect(manager.getValidAccessToken()).resolves.toBe("ya29.restart");
    expect(calls).toEqual(["/oauth/nonce", "/oauth/lease"]);
    expect(calls).not.toContain("/oauth/pair");
    expect(manager.hasValidLease()).toBe(true);
  });

  it("falls back to a clear re-enrol required state when the pairing has expired (410)", async () => {
    const { manager, calls } = restart({ leaseStatus: 410 });
    await expect(manager.getValidAccessToken()).rejects.toMatchObject({ code: "expired" });
    expect(manager.enrollment).toEqual({ pairId: null, status: "not_enrolled", expiresAtMs: null });
    expect(manager.enrolled).toBe(false);
    await expect(manager.getValidAccessToken()).rejects.toMatchObject({ code: "not_enrolled" });
    expect(calls).not.toContain("/oauth/pair");
  });

  it("falls back to a clear re-enrol required state when the lease is revoked (403)", async () => {
    const { manager } = restart({ leaseStatus: 403 });
    await expect(manager.getValidAccessToken()).rejects.toMatchObject({ code: "revoked" });
    expect(manager.enrollment.status).toBe("not_enrolled");
    expect(manager.enrollment.pairId).toBeNull();
    expect(manager.enrolled).toBe(false);
  });

  it("never emits an access token in the enrollment state it reports", async () => {
    const seen: EnrollmentView[] = [];
    const { manager } = restart({ onEnrollment: (state) => { seen.push(state); } });
    await manager.getValidAccessToken();
    expect(seen.length).toBeGreaterThan(0);
    expect(JSON.stringify(seen)).not.toContain("ya29");
    expect(Object.keys(seen[0]).sort()).toEqual(["expiresAtMs", "pairId", "status"]);
    expect(seen.at(-1)!.status).toBe("enrolled");
  });
});
