import { describe, expect, it } from "vitest";
import { BrokerError, type BrokerRequest, type BrokerResponse } from "../src/auth/broker-client";
import { generateDeviceIdentity, sealLeaseEnvelope, signUtf8Base64Url, type DeviceIdentity, type LeasePayload } from "../src/auth/device-identity";
import { LeaseManager } from "../src/auth/lease-manager";
import { BrokerClient } from "../src/auth/broker-client";

const BASE_URL = "https://broker.example.test/gdrive-stream-oauth";
const ENROLLMENT_CODE = "ENROLL-TEST-CODE";
const PROOF_MESSAGE = "gdrive-stream-pairing-proof-message";

interface Harness {
  manager: LeaseManager;
  calls: BrokerRequest[];
  opened: string[];
  claimProofs: string[];
  leaseProofs: string[];
  advance: (ms: number) => void;
  now: () => number;
}

function harness(options: {
  identity: DeviceIdentity;
  leasePayloads?: LeasePayload[];
  claimStatuses?: number[];
  leaseStatus?: number;
  initialPairId?: string;
  rootFolderName?: string;
  startMs?: number;
}): Harness {
  const identity = options.identity;
  let nowMs = options.startMs ?? 1_000_000;
  let pairExpiresAtMs = nowMs + 600_000;
  const calls: BrokerRequest[] = [];
  const opened: string[] = [];
  const claimProofs: string[] = [];
  const leaseProofs: string[] = [];
  const claimStatuses = [...(options.claimStatuses ?? [])];
  const payloads = [...(options.leasePayloads ?? [])];
  const nextPayload = (): LeasePayload => {
    const payload = payloads.shift();
    if (!payload) throw new Error("no lease payload queued");
    return { ...payload, expiresAtMs: nowMs + payload.expiresAtMs };
  };

  const transport = async (request: BrokerRequest): Promise<BrokerResponse> => {
    calls.push(request);
    const body = JSON.parse(request.body) as Record<string, unknown>;
    if (request.url.endsWith("/oauth/pair")) {
      pairExpiresAtMs = nowMs + 10_000;
      return {
        status: 201,
        json: {
          pairId: "b".repeat(64),
          oauthState: "s".repeat(43),
          proofMessage: PROOF_MESSAGE,
          expiresAtMs: pairExpiresAtMs,
          authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth?client_id=test-client"
        }
      };
    }
    if (request.url.endsWith("/oauth/claim")) {
      claimProofs.push(String(body.proof));
      const status = claimStatuses.length ? claimStatuses.shift()! : 200;
      if (status !== 200) return { status, json: { error: status === 409 ? "not_authorized_yet" : "revoked" } };
      return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, nextPayload()), expiresAtMs: nowMs + 600_000 } };
    }
    if (request.url.endsWith("/oauth/nonce")) {
      return { status: 200, json: { nonce: "nonce-single-use", expiresAtMs: nowMs + 30_000 } };
    }
    if (request.url.endsWith("/oauth/lease")) {
      leaseProofs.push(String(body.proof));
      const status = options.leaseStatus ?? 200;
      if (status !== 200) return { status, json: { error: "expired" } };
      return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, nextPayload()), expiresAtMs: nowMs + 600_000 } };
    }
    throw new Error(`unexpected ${request.url}`);
  };

  const manager = new LeaseManager({
    broker: new BrokerClient({ baseUrl: BASE_URL, request: transport }),
    identity,
    openAuthorizationUrl: (url) => { opened.push(url); },
    now: () => nowMs,
    sleep: async (ms) => { nowMs += ms; },
    claimPollIntervalMs: 2_000,
    renewalLeadMs: 60_000,
    rootFolderName: options.rootFolderName ?? "example-test-root",
    initialPairId: options.initialPairId
  });
  return { manager, calls, opened, claimProofs, leaseProofs, advance: (ms) => { nowMs += ms; }, now: () => nowMs };
}

const payload = (token: string, lifetimeMs: number): LeasePayload => ({ accessToken: token, expiresAtMs: lifetimeMs, scope: "drive.readonly", allowedRootName: "example-test-root" });

describe("lease manager", () => {
  it("pairs, opens the consent URL and polls through not_authorized_yet until consent completes", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, claimStatuses: [409, 409], leasePayloads: [payload("ya29.lease-1", 600_000)] });

    const state = await h.manager.enroll(ENROLLMENT_CODE);

    expect(h.opened).toEqual(["https://accounts.google.com/o/oauth2/v2/auth?client_id=test-client"]);
    expect(h.claimProofs).toHaveLength(3);
    for (const proof of h.claimProofs) expect(proof).toBe(signUtf8Base64Url(identity, PROOF_MESSAGE));
    expect(state.allowedRootName).toBe("example-test-root");
    expect(h.manager.enrolled).toBe(true);
    await expect(h.manager.getValidAccessToken()).resolves.toBe("ya29.lease-1");
  });

  it("stops polling at the pairing expiry and reports expired", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, claimStatuses: [409, 409, 409, 409, 409, 409, 409, 409] });

    await expect(h.manager.enroll(ENROLLMENT_CODE)).rejects.toMatchObject({ code: "expired" });
    expect(h.claimProofs.length).toBeGreaterThan(1);
    expect(h.claimProofs.length).toBeLessThanOrEqual(6);
    expect(h.manager.enrolled).toBe(false);
  });

  it("renews before expiry through nonce + lease without re-pairing", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, leasePayloads: [payload("ya29.lease-1", 300_000), payload("ya29.lease-2", 300_000)] });
    await h.manager.enroll(ENROLLMENT_CODE);
    const pairCalls = h.calls.filter((call) => call.url.endsWith("/oauth/pair")).length;

    await expect(h.manager.getValidAccessToken()).resolves.toBe("ya29.lease-1");
    h.advance(250_000);
    expect(h.manager.hasValidLease()).toBe(false);
    await expect(h.manager.getValidAccessToken()).resolves.toBe("ya29.lease-2");

    expect(h.calls.filter((call) => call.url.endsWith("/oauth/pair")).length).toBe(pairCalls);
    expect(h.calls.some((call) => call.url.endsWith("/oauth/nonce"))).toBe(true);
    expect(h.calls.some((call) => call.url.endsWith("/oauth/lease"))).toBe(true);
    expect(h.leaseProofs[0]).toBe(signUtf8Base64Url(identity, "nonce-single-use"));
  });

  it("returns the cached token while the lease is still valid", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, leasePayloads: [payload("ya29.lease-1", 300_000)] });
    await h.manager.enroll(ENROLLMENT_CODE);
    await h.manager.getValidAccessToken();
    const afterFirst = h.calls.length;
    h.advance(10_000);
    await expect(h.manager.getValidAccessToken()).resolves.toBe("ya29.lease-1");
    expect(h.calls.length).toBe(afterFirst);
  });

  it("shares a single renewal between concurrent callers", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, leasePayloads: [payload("ya29.lease-1", 300_000), payload("ya29.lease-2", 300_000)], initialPairId: "b".repeat(64) });

    const [first, second] = await Promise.all([h.manager.getValidAccessToken(), h.manager.getValidAccessToken()]);
    expect([first, second]).toEqual(["ya29.lease-1", "ya29.lease-1"]);
    expect(h.calls.filter((call) => call.url.endsWith("/oauth/nonce"))).toHaveLength(1);
    expect(h.calls.filter((call) => call.url.endsWith("/oauth/lease"))).toHaveLength(1);
  });

  it("refuses a lease that is not scoped to the beta root", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, leasePayloads: [{ accessToken: "ya29.wrong-root", expiresAtMs: 300_000, scope: "drive.readonly", allowedRootName: "production-root" }] });

    await expect(h.manager.enroll(ENROLLMENT_CODE)).rejects.toThrow(/example-test-root/);
    expect(h.manager.enrolled).toBe(false);
    await expect(h.manager.getValidAccessToken()).rejects.toMatchObject({ code: "not_enrolled" });
  });

  it("requires re-enrollment after revocation and forgets the token on clear", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, leasePayloads: [payload("ya29.lease-1", 300_000), payload("ya29.lease-2", 300_000)], leaseStatus: 403 });
    await h.manager.enroll(ENROLLMENT_CODE);
    h.advance(250_000);

    await expect(h.manager.getValidAccessToken()).rejects.toMatchObject({ code: "revoked" });
    expect(h.manager.enrolled).toBe(false);
    await expect(h.manager.getValidAccessToken()).rejects.toMatchObject({ code: "not_enrolled" });

    h.manager.clear();
    expect(h.manager.hasValidLease()).toBe(false);
    expect(h.manager.enrollment).toEqual({ pairId: null, expiresAtMs: null, status: "not_enrolled" });
  });

  it("rejects use before enrollment without contacting the broker", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity });
    await expect(h.manager.getValidAccessToken()).rejects.toBeInstanceOf(BrokerError);
    await expect(h.manager.getValidAccessToken()).rejects.toMatchObject({ code: "not_enrolled" });
    expect(h.calls).toHaveLength(0);
  });

  it("reports enrollment state without exposing the access token", async () => {
    const identity = generateDeviceIdentity();
    const seen: Array<Record<string, unknown>> = [];
    const manager = new LeaseManager({
      broker: new BrokerClient({ baseUrl: BASE_URL, request: async (request) => {
        if (request.url.endsWith("/oauth/pair")) return { status: 201, json: { pairId: "c".repeat(64), oauthState: "s", proofMessage: PROOF_MESSAGE, expiresAtMs: 9_999_999, authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth" } };
        return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, payload("ya29.lease-1", 300_000)), expiresAtMs: 9_999_999 } };
      } }),
      identity,
      openAuthorizationUrl: () => undefined,
      now: () => 1_000_000,
      sleep: async () => undefined,
      onEnrollment: (state) => { seen.push(state as unknown as Record<string, unknown>); }
    });
    await manager.enroll(ENROLLMENT_CODE);
    expect(seen.length).toBeGreaterThan(0);
    expect(Object.keys(seen[0]).sort()).toEqual(["expiresAtMs", "pairId", "status"]);
    const serialized = JSON.stringify(seen);
    expect(serialized).not.toContain("ya29");
    expect(serialized).not.toContain("accessToken");
  });

  /**
   * Regression: a bare pairing used to be reported as `enrolled`, so the UI
   * announced success before Google consent had been granted and then flipped
   * back to not enrolled once the pairing window closed.
   */
  it("never reports enrolled between pairing and the consent approval", async () => {
    const identity = generateDeviceIdentity();
    const seen: string[] = [];
    const statusWhenBrowserOpened: string[] = [];
    const manager = new LeaseManager({
      broker: new BrokerClient({ baseUrl: BASE_URL, request: async (request) => {
        if (request.url.endsWith("/oauth/pair")) {
          return { status: 201, json: { pairId: "d".repeat(64), oauthState: "s", proofMessage: PROOF_MESSAGE, expiresAtMs: 1_010_000, authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth" } };
        }
        if (request.url.endsWith("/oauth/claim")) {
          return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, payload("ya29.lease-1", 300_000)), expiresAtMs: 1_600_000 } };
        }
        throw new Error(`unexpected ${request.url}`);
      } }),
      identity,
      openAuthorizationUrl: () => { statusWhenBrowserOpened.push(manager.enrollment.status); },
      now: () => 1_000_000,
      sleep: async () => undefined,
      onEnrollment: (state) => { seen.push(state.status); }
    });

    await manager.enroll(ENROLLMENT_CODE);

    expect(statusWhenBrowserOpened).toEqual(["awaiting_consent"]);
    expect(seen).toContain("awaiting_consent");
    expect(seen.indexOf("awaiting_consent")).toBeLessThan(seen.indexOf("enrolled"));
    expect(manager.enrollment.status).toBe("enrolled");
  });

  it("returns to not_enrolled with no pair id when the consent window expires", async () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, claimStatuses: [409, 409, 409, 409, 409, 409, 409, 409] });

    await expect(h.manager.enroll(ENROLLMENT_CODE)).rejects.toMatchObject({ code: "expired" });
    expect(h.manager.enrollment).toEqual({ pairId: null, status: "not_enrolled", expiresAtMs: null });
  });

  it("drops the pending pairing when the consent poll aborts with a transport failure", async () => {
    const identity = generateDeviceIdentity();
    const manager = new LeaseManager({
      broker: new BrokerClient({ baseUrl: BASE_URL, request: async (request) => {
        if (request.url.endsWith("/oauth/pair")) {
          return { status: 201, json: { pairId: "e".repeat(64), oauthState: "s", proofMessage: PROOF_MESSAGE, expiresAtMs: 1_600_000, authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth" } };
        }
        throw new Error("network down");
      } }),
      identity,
      openAuthorizationUrl: () => undefined,
      now: () => 1_000_000,
      sleep: async () => undefined
    });

    await expect(manager.enroll(ENROLLMENT_CODE)).rejects.toThrow();
    // A stuck awaiting_consent state would strand the view behind a pairing that
    // can no longer complete.
    expect(manager.enrollment).toEqual({ pairId: null, status: "not_enrolled", expiresAtMs: null });
  });

  it("treats a persisted pairing as authorised across a restart, without a lease", () => {
    const identity = generateDeviceIdentity();
    const h = harness({ identity, initialPairId: "b".repeat(64) });

    expect(h.manager.enrollment.status).toBe("enrolled");
    expect(h.manager.enrolled).toBe(false);
  });
});
