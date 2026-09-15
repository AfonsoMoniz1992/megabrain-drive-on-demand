import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GOOGLE_DRIVE_READONLY_SCOPE, parseBrokerRuntimeConfig } from "../broker/src/config";
import { EnrollmentStore, deviceSigningKeyFingerprint } from "../broker/src/enrollment-store";
import type { OAuthTokenTransport, OAuthTransportRequest } from "../broker/src/google-oauth-client";
import { unsealLease, type SealedLease } from "../broker/src/lease-sealer";
import { PairingStore } from "../broker/src/pairing-store";
import { EncryptedRefreshTokenStore } from "../broker/src/refresh-token-store";
import { createBrokerServer } from "../broker/src/server";

const CALLBACK_URI = "https://broker.example.test/oauth/google/callback";
const CLIENT_SECRET = "test-client-secret-must-not-leak";
const REFRESH_TOKEN = "1//0g-refresh-token-must-not-leak";
const CALLBACK_ACCESS_TOKEN = "ya29.callback-access-token-must-not-leak";
const REFRESHED_ACCESS_TOKEN = "ya29.refreshed-access-token-must-stay-sealed";
const CODE = "test-authorization-code-must-not-leak";
const CALLBACK_PATH = "/oauth/google/callback";

type Server = ReturnType<typeof createBrokerServer>;

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function ed25519Device(): { publicKeyPem: string; sign: (data: Buffer) => string } {
  const keys = generateKeyPairSync("ed25519");
  return {
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    sign: (data: Buffer) => sign(null, data, keys.privateKey).toString("base64url")
  };
}

function x25519Device(): { publicKeyPem: string; privateKeyPem: string } {
  const keys = generateKeyPairSync("x25519");
  return {
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

interface Harness {
  baseUrl: string;
  enrollmentStore: EnrollmentStore;
  pairingStore: PairingStore;
  refreshTokenStore: EncryptedRefreshTokenStore;
  requests: OAuthTransportRequest[];
  directory: string;
  setNow: (value: number) => void;
}

async function startHarness(options: { transportFails?: boolean; allowedRootName?: string } = {}): Promise<Harness> {
  const directory = mkdtempSync(join(tmpdir(), "mbrt-claim-"));
  directories.push(directory);
  const enrollmentStore = new EnrollmentStore();
  const pairingStore = new PairingStore();
  const refreshTokenStore = new EncryptedRefreshTokenStore(
    join(directory, "protected", "refresh-token.bin"),
    Buffer.alloc(32, 7)
  );
  const requests: OAuthTransportRequest[] = [];
  const transport: OAuthTokenTransport = async (request) => {
    requests.push(request);
    if (options.transportFails) return { status: 400, body: JSON.stringify({ error: "invalid_grant" }) };
    const params = new URLSearchParams(request.body);
    if (params.get("grant_type") === "authorization_code") {
      return {
        status: 200,
        body: JSON.stringify({
          access_token: CALLBACK_ACCESS_TOKEN,
          token_type: "Bearer",
          refresh_token: REFRESH_TOKEN,
          expires_in: 3_600,
          scope: GOOGLE_DRIVE_READONLY_SCOPE
        })
      };
    }
    return {
      status: 200,
      body: JSON.stringify({ access_token: REFRESHED_ACCESS_TOKEN, token_type: "Bearer", expires_in: 3_600, scope: GOOGLE_DRIVE_READONLY_SCOPE })
    };
  };
  let nowMs = 1_000;
  const server = createBrokerServer({
    now: () => nowMs,
    pairingStore,
    enrollmentStore,
    refreshTokenStore,
    allowedRootName: options.allowedRootName ?? "example-test-root",
    oauth: {
      config: parseBrokerRuntimeConfig({
        googleClientId: "test-client.apps.googleusercontent.com",
        googleCallbackUri: CALLBACK_URI,
        googleDriveScope: GOOGLE_DRIVE_READONLY_SCOPE,
        pairingTtlMs: 300_000,
        pairingCapacity: 50,
        pairingRateLimitMaxAttempts: 100,
        pairingRateLimitWindowMs: 60_000
      }),
      clientSecret: CLIENT_SECRET
    },
    oauthTransport: transport
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server address missing");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    enrollmentStore,
    pairingStore,
    refreshTokenStore,
    requests,
    directory,
    setNow: (value: number) => {
      nowMs = value;
    }
  };
}

interface Pairing {
  pairId: string;
  oauthState: string;
  proofMessage: string;
}

async function pairDevice(
  harness: Harness,
  device: { publicKeyPem: string },
  encryption: { publicKeyPem: string }
): Promise<Pairing> {
  const { code } = harness.enrollmentStore.issue({
    nowMs: 1_000,
    ttlMs: 300_000,
    expectedDeviceFingerprint: deviceSigningKeyFingerprint(device.publicKeyPem)
  });
  const response = await fetch(`${harness.baseUrl}/oauth/pair`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      devicePublicKeyPem: device.publicKeyPem,
      deviceEncryptionPublicKeyPem: encryption.publicKeyPem,
      enrollmentCode: code
    })
  });
  expect(response.status).toBe(201);
  return (await response.json()) as Pairing;
}

async function authorize(harness: Harness, pairing: Pairing): Promise<number> {
  const url = `${harness.baseUrl}${CALLBACK_PATH}?${new URLSearchParams({ state: pairing.oauthState, code: CODE }).toString()}`;
  return (await fetch(url)).status;
}

function post(harness: Harness, path: string, body: object): Promise<Response> {
  return fetch(`${harness.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}

function collectFiles(directory: string): string {
  const paths = readdirSync(directory, { recursive: true }) as string[];
  return paths
    .filter((relative) => statSync(join(directory, relative)).isFile())
    .map((relative) => readFileSync(join(directory, relative), "utf8"))
    .join("\n");
}

describe("device-bound sealed lease claim", () => {
  it("claims a sealed lease once and never exposes the raw access token", async () => {
    const captured: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        captured.push(args.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" "));
      });
    }

    const harness = await startHarness();
    const device = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pairing)).toBe(200);

    const response = await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { sealedLease: SealedLease; expiresAtMs: number };
    expect(Object.keys(body).sort()).toEqual(["expiresAtMs", "sealedLease"]);

    const payload = unsealLease({ envelope: body.sealedLease, deviceEncryptionPrivateKeyPem: encryption.privateKeyPem }) as {
      accessToken: string;
      expiresAtMs: number;
      scope: string;
      allowedRootName: string;
    };
    expect(payload).toEqual({
      accessToken: REFRESHED_ACCESS_TOKEN,
      expiresAtMs: body.expiresAtMs,
      scope: GOOGLE_DRIVE_READONLY_SCOPE,
      allowedRootName: "example-test-root"
    });
    expect(body.expiresAtMs).toBe(1_000 + 3_600_000);

    // Durable post-claim state that still permits lease renewal.
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "enrolled" });

    const serialized = JSON.stringify(body);
    for (const secret of [REFRESHED_ACCESS_TOKEN, CALLBACK_ACCESS_TOKEN, REFRESH_TOKEN, CLIENT_SECRET, CODE]) {
      expect(serialized).not.toContain(secret);
    }
    const files = collectFiles(harness.directory);
    expect(files).not.toContain(REFRESHED_ACCESS_TOKEN);
    expect(files).not.toContain(CALLBACK_ACCESS_TOKEN);
    expect(captured.join("\n")).not.toContain(REFRESHED_ACCESS_TOKEN);
    expect(captured.join("\n")).not.toContain(REFRESH_TOKEN);

    // The claim is one-time: a second attempt is refused.
    const second = await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) });
    expect(second.status).toBe(409);
    expect(await second.json()).toEqual({ error: "not_authorized_yet" });
  });

  it("requires an authorized pairing and refuses pending or mid-callback pairings", async () => {
    const harness = await startHarness();
    const device = ed25519Device();
    const encryption = x25519Device();

    const pending = await pairDevice(harness, device, encryption);
    const pendingClaim = await post(harness, "/oauth/claim", { pairId: pending.pairId, proof: device.sign(Buffer.from(pending.proofMessage)) });
    expect(pendingClaim.status).toBe(409);

    const failing = await startHarness({ transportFails: true });
    const device2 = ed25519Device();
    const encryption2 = x25519Device();
    const consumed = await pairDevice(failing, device2, encryption2);
    expect(await authorize(failing, consumed)).toBe(400);
    expect(failing.pairingStore.debugRecord(consumed.pairId)).toEqual({ hasPlainPairId: false, status: "callback_state_consumed" });
    const midClaim = await post(failing, "/oauth/claim", { pairId: consumed.pairId, proof: device2.sign(Buffer.from(consumed.proofMessage)) });
    expect(midClaim.status).toBe(409);
  });

  it("rejects an invalid proof and an expired or revoked pairing", async () => {
    const harness = await startHarness();
    const owner = ed25519Device();
    const attacker = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, owner, encryption);
    expect(await authorize(harness, pairing)).toBe(200);

    const badProof = await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: attacker.sign(Buffer.from(pairing.proofMessage)) });
    expect(badProof.status).toBe(403);
    expect(await badProof.json()).toEqual({ error: "invalid_proof" });
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });

    const revoked = await pairDevice(harness, owner, encryption);
    expect(await authorize(harness, revoked)).toBe(200);
    expect(harness.pairingStore.revoke({ pairId: revoked.pairId, nowMs: 2_000 })).toBe(true);
    const revokedClaim = await post(harness, "/oauth/claim", { pairId: revoked.pairId, proof: owner.sign(Buffer.from(revoked.proofMessage)) });
    expect(revokedClaim.status).toBe(403);
    expect(await revokedClaim.json()).toEqual({ error: "revoked" });

    const expiring = await pairDevice(harness, owner, encryption);
    expect(await authorize(harness, expiring)).toBe(200);
    harness.setNow(301_001);
    const expiredClaim = await post(harness, "/oauth/claim", { pairId: expiring.pairId, proof: owner.sign(Buffer.from(expiring.proofMessage)) });
    expect(expiredClaim.status).toBe(410);
    expect(await expiredClaim.json()).toEqual({ error: "expired" });
  });

  it("renews a sealed lease through nonce + lease without re-pairing and stays enrolled", async () => {
    const harness = await startHarness();
    const device = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pairing)).toBe(200);
    const claimed = await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) });
    expect(claimed.status).toBe(200);

    const nonceResponse = await post(harness, "/oauth/nonce", { pairId: pairing.pairId });
    expect(nonceResponse.status).toBe(200);
    const { nonce, expiresAtMs } = (await nonceResponse.json()) as { nonce: string; expiresAtMs: number };
    expect(nonce).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(expiresAtMs).toBe(1_000 + 120_000);

    const lease = await post(harness, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce,
      proof: device.sign(Buffer.from(nonce, "base64url"))
    });
    expect(lease.status).toBe(200);
    const leaseBody = (await lease.json()) as { sealedLease: SealedLease; expiresAtMs: number };
    expect(Object.keys(leaseBody).sort()).toEqual(["expiresAtMs", "sealedLease"]);
    const payload = unsealLease({ envelope: leaseBody.sealedLease, deviceEncryptionPrivateKeyPem: encryption.privateKeyPem }) as {
      accessToken: string;
      allowedRootName: string;
    };
    expect(payload.accessToken).toBe(REFRESHED_ACCESS_TOKEN);
    expect(payload.allowedRootName).toBe("example-test-root");

    // Renewal does not require re-pairing and the pairing stays enrolled.
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "enrolled" });
    expect(harness.requests.map((request) => new URLSearchParams(request.body).get("grant_type"))).toEqual([
      "authorization_code",
      "refresh_token",
      "refresh_token"
    ]);
  });

  it("seals the operator-configured harmless root name into renewed leases", async () => {
    const harness = await startHarness({ allowedRootName: "operator-test-root" });
    const device = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pairing)).toBe(200);
    expect((await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) })).status).toBe(200);
    const nonce = (await (await post(harness, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };
    const lease = await post(harness, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce: nonce.nonce,
      proof: device.sign(Buffer.from(nonce.nonce, "base64url"))
    });
    const body = (await lease.json()) as { sealedLease: SealedLease };
    const payload = unsealLease({ envelope: body.sealedLease, deviceEncryptionPrivateKeyPem: encryption.privateKeyPem }) as { allowedRootName: string };
    expect(payload.allowedRootName).toBe("operator-test-root");
  });

  it("consumes a nonce exactly once and rejects an expired nonce", async () => {
    const harness = await startHarness();
    const device = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pairing)).toBe(200);
    await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) });

    const first = (await (await post(harness, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };
    const proof = device.sign(Buffer.from(first.nonce, "base64url"));
    expect((await post(harness, "/oauth/lease", { pairId: pairing.pairId, nonce: first.nonce, proof })).status).toBe(200);
    // Replay of the consumed nonce fails closed.
    const replay = await post(harness, "/oauth/lease", { pairId: pairing.pairId, nonce: first.nonce, proof });
    expect(replay.status).toBe(403);
    expect(await replay.json()).toEqual({ error: "invalid_nonce" });

    // Expiry: a nonce becomes unusable at its TTL boundary.
    const expiring = (await (await post(harness, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };
    harness.setNow(121_000);
    const expired = await post(harness, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce: expiring.nonce,
      proof: device.sign(Buffer.from(expiring.nonce, "base64url"))
    });
    expect(expired.status).toBe(403);
    expect(await expired.json()).toEqual({ error: "invalid_nonce" });
  });

  it("only leases to an enrolled pairing with a valid device signature", async () => {
    const harness = await startHarness();
    const device = ed25519Device();
    const attacker = ed25519Device();
    const encryption = x25519Device();

    // Not enrolled yet (still authorized): no nonce is issued.
    const pending = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pending)).toBe(200);
    const early = await post(harness, "/oauth/nonce", { pairId: pending.pairId });
    expect(early.status).toBe(409);
    expect(await early.json()).toEqual({ error: "not_authorized_yet" });

    // Unknown pairings never receive a nonce.
    const unknown = await post(harness, "/oauth/nonce", { pairId: "0".repeat(64) });
    expect(unknown.status).toBe(403);
    expect(await unknown.json()).toEqual({ error: "revoked" });

    // Enrolled, but a wrong signature is refused.
    await post(harness, "/oauth/claim", { pairId: pending.pairId, proof: device.sign(Buffer.from(pending.proofMessage)) });
    const { nonce } = (await (await post(harness, "/oauth/nonce", { pairId: pending.pairId })).json()) as { nonce: string };
    const forged = await post(harness, "/oauth/lease", {
      pairId: pending.pairId,
      nonce,
      proof: attacker.sign(Buffer.from(nonce, "base64url"))
    });
    expect(forged.status).toBe(403);
    expect(await forged.json()).toEqual({ error: "invalid_proof" });
  });

  it("revocation blocks any further lease", async () => {
    const harness = await startHarness();
    const device = ed25519Device();
    const encryption = x25519Device();
    const pairing = await pairDevice(harness, device, encryption);
    expect(await authorize(harness, pairing)).toBe(200);
    await post(harness, "/oauth/claim", { pairId: pairing.pairId, proof: device.sign(Buffer.from(pairing.proofMessage)) });

    const { nonce } = (await (await post(harness, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };
    expect(harness.pairingStore.revoke({ pairId: pairing.pairId, nowMs: 2_000 })).toBe(true);

    const afterRevokeNonce = await post(harness, "/oauth/nonce", { pairId: pairing.pairId });
    expect(afterRevokeNonce.status).toBe(403);
    expect(await afterRevokeNonce.json()).toEqual({ error: "revoked" });

    const afterRevokeLease = await post(harness, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce,
      proof: device.sign(Buffer.from(nonce, "base64url"))
    });
    expect(afterRevokeLease.status).toBe(403);
    expect(await afterRevokeLease.json()).toEqual({ error: "revoked" });
  });
});
