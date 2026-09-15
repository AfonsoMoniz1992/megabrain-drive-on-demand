import { generateKeyPairSync } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import { parseBrokerRuntimeConfig } from "../broker/src/config";
import { deviceSigningKeyFingerprint, EnrollmentStore } from "../broker/src/enrollment-store";
import { GoogleOAuthClient } from "../broker/src/google-oauth-client";
// The broker requires an explicit allowed root; tests name a harmless one.
import { createTestBrokerServer as createBrokerServer } from "./support/broker-server";

const servers: Array<ReturnType<typeof createBrokerServer>> = [];
afterEach(async () => { await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve())))); });

/** A device whose operator-approved signing-key fingerprint is known up front. */
function device(): { publicKeyPem: string; fingerprint: string } {
  const publicKeyPem = generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
  return { publicKeyPem, fingerprint: deviceSigningKeyFingerprint(publicKeyPem) };
}

function devicePublicKeyPem(): string {
  return device().publicKeyPem;
}

function deviceEncryptionPublicKeyPem(): string {
  return generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

async function start(server: ReturnType<typeof createBrokerServer>): Promise<string> {
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server address missing");
  return `http://127.0.0.1:${address.port}`;
}

function pairBody(enrollmentCode: string, device = devicePublicKeyPem()): string {
  return JSON.stringify({
    devicePublicKeyPem: device,
    deviceEncryptionPublicKeyPem: deviceEncryptionPublicKeyPem(),
    enrollmentCode
  });
}

describe("self-hosted broker HTTP shell", () => {
  it("exposes a token-free health endpoint", async () => {
    const url = await start(createBrokerServer({ now: () => 1_000 }));
    const response = await fetch(`${url}/health`);
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ service: "gdrive-stream-broker", status: "ok" });
  });

  it("creates a device-bound pairing without returning OAuth or token material", async () => {
    const enrollmentStore = new EnrollmentStore();
    const approved = device();
    const { code } = enrollmentStore.issue({ nowMs: 1_000, ttlMs: 300_000, expectedDeviceFingerprint: approved.fingerprint });
    const url = await start(createBrokerServer({ now: () => 1_000, enrollmentStore }));
    const response = await fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: pairBody(code, approved.publicKeyPem) });
    expect(response.status).toBe(201);
    const body = await response.json() as Record<string, unknown>;
    expect(body.pairId).toMatch(/^[a-f0-9]{64}$/);
    expect(body.oauthState).toEqual(expect.any(String));
    expect(body).not.toHaveProperty("authorizationUrl");
    expect(body).not.toHaveProperty("token");
    expect(body).not.toHaveProperty("authorizationCode");
    expect(JSON.stringify(body)).not.toContain(code);
  });

  it("rejects raw OAuth configuration before serving pairing", () => {
    expect(() => createBrokerServer({
      oauth: {
        config: {
          googleClientId: "test-client.apps.googleusercontent.com",
          googleCallbackUri: "http://broker.example.test/oauth/callback",
          googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
          pairingTtlMs: 300_000,
          pairingCapacity: 50,
          pairingRateLimitMaxAttempts: 3,
          pairingRateLimitWindowMs: 60_000
        }
      }
    } as never)).toThrow("Invalid googleCallbackUri");
  });

  it("returns a safe Google authorization URL only with explicit OAuth configuration", async () => {
    const config = parseBrokerRuntimeConfig({
      googleClientId: "test-client.apps.googleusercontent.com",
      googleCallbackUri: "https://broker.example.test/oauth/callback",
      googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
      pairingTtlMs: 300_000,
      pairingCapacity: 50,
      pairingRateLimitMaxAttempts: 3,
      pairingRateLimitWindowMs: 60_000
    });
    const enrollmentStore = new EnrollmentStore();
    const approved = device();
    const { code } = enrollmentStore.issue({ nowMs: 1_000, ttlMs: 300_000, expectedDeviceFingerprint: approved.fingerprint });
    const url = await start(createBrokerServer({
      now: () => 1_000,
      enrollmentStore,
      oauth: { config }
    }));

    const response = await fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: pairBody(code, approved.publicKeyPem) });
    expect(response.status).toBe(201);
    const body = await response.json() as Record<string, unknown>;
    expect(body.authorizationUrl).toEqual(expect.any(String));
    const authorizationUrl = body.authorizationUrl as string;
    const authorizationQuery = new URL(authorizationUrl).searchParams;
    expect(authorizationQuery.get("client_id")).toBe(config.googleClientId);
    expect(authorizationQuery.get("redirect_uri")).toBe(config.googleCallbackUri);
    expect(authorizationQuery.get("code_challenge_method")).toBe("S256");
    expect(authorizationUrl).not.toContain(body.pairId as string);
    expect(authorizationUrl).not.toContain("client_secret");
    expect(authorizationUrl).not.toContain("token");
    expect(body).not.toHaveProperty("pkceVerifier");
  });

  it("constructs authorization URLs from the supplied config despite an injected mismatched client", async () => {
    const config = parseBrokerRuntimeConfig({
      googleClientId: "configured-client.apps.googleusercontent.com",
      googleCallbackUri: "https://broker.example.test/oauth/callback",
      googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
      pairingTtlMs: 300_000,
      pairingCapacity: 50,
      pairingRateLimitMaxAttempts: 3,
      pairingRateLimitWindowMs: 60_000
    });
    const mismatchedClient = new GoogleOAuthClient({
      googleClientId: "attacker-client.apps.googleusercontent.com",
      googleCallbackUri: "https://attacker.example.test/callback",
      googleDriveScope: "https://www.googleapis.com/auth/drive" as never
    });
    const enrollmentStore = new EnrollmentStore();
    const approved = device();
    const { code } = enrollmentStore.issue({ nowMs: 1_000, ttlMs: 300_000, expectedDeviceFingerprint: approved.fingerprint });
    const url = await start(createBrokerServer({
      now: () => 1_000,
      enrollmentStore,
      oauth: { config, googleOAuthClient: mismatchedClient }
    } as never));

    const response = await fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: pairBody(code, approved.publicKeyPem) });
    expect(response.status).toBe(201);
    const authorizationUrl = (await response.json() as { authorizationUrl: string }).authorizationUrl;
    const authorizationQuery = new URL(authorizationUrl).searchParams;
    expect(authorizationQuery.get("client_id")).toBe(config.googleClientId);
    expect(authorizationQuery.get("redirect_uri")).toBe(config.googleCallbackUri);
    expect(authorizationQuery.get("scope")).toBe(config.googleDriveScope);
    expect(authorizationUrl).not.toContain("attacker-client");
    expect(authorizationUrl).not.toContain("attacker.example.test");
    expect(authorizationUrl).not.toContain("auth%2Fdrive&");
  });

  it("rate-limits pairing creation and releases expired rate-limit entries", async () => {
    let now = 1_000;
    const enrollmentStore = new EnrollmentStore();
    const devices = [0, 1, 2, 3].map(() => device());
    const codes = devices.map((entry) => enrollmentStore.issue({ nowMs: 1_000, ttlMs: 3_600_000, expectedDeviceFingerprint: entry.fingerprint }).code);
    const url = await start(createBrokerServer({ now: () => now, enrollmentStore, maxPairAttemptsPerWindow: 2, rateLimitWindowMs: 60_000 }));
    const pair = (index: number) => fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: pairBody(codes[index], devices[index].publicKeyPem) });
    expect((await pair(0)).status).toBe(201);
    expect((await pair(1)).status).toBe(201);
    expect((await pair(2)).status).toBe(429);
    now += 60_000;
    expect((await pair(3)).status).toBe(201);
  });
});

describe("self-hosted enrollment gate on POST /oauth/pair", () => {
  it("requires a valid enrollment code and creates no pairing without one", async () => {
    const config = parseBrokerRuntimeConfig({
      googleClientId: "test-client.apps.googleusercontent.com",
      googleCallbackUri: "https://broker.example.test/oauth/callback",
      googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
      pairingTtlMs: 300_000,
      pairingCapacity: 50,
      pairingRateLimitMaxAttempts: 100,
      pairingRateLimitWindowMs: 60_000
    });
    const enrollmentStore = new EnrollmentStore();
    const url = await start(createBrokerServer({ now: () => 1_000, enrollmentStore, oauth: { config } }));

    for (const body of [
      { devicePublicKeyPem: devicePublicKeyPem(), deviceEncryptionPublicKeyPem: deviceEncryptionPublicKeyPem() },
      { devicePublicKeyPem: devicePublicKeyPem(), deviceEncryptionPublicKeyPem: deviceEncryptionPublicKeyPem(), enrollmentCode: "ZZZZ-ZZZZ-ZZZZ-ZZZZ" },
      { devicePublicKeyPem: devicePublicKeyPem(), deviceEncryptionPublicKeyPem: deviceEncryptionPublicKeyPem(), enrollmentCode: 42 }
    ]) {
      const response = await fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
      expect(response.status).toBe(403);
      const payload = await response.json() as Record<string, unknown>;
      expect(payload).toEqual({ error: "enrollment_required" });
      expect(payload).not.toHaveProperty("pairId");
      expect(payload).not.toHaveProperty("authorizationUrl");
    }
    expect(enrollmentStore.debugCounts().used).toBe(0);
  });

  it("rejects a used, expired or fingerprint-mismatched enrollment code", async () => {
    let now = 1_000;
    const enrollmentStore = new EnrollmentStore();
    const approved = device();
    const other = device();
    const url = await start(createBrokerServer({ now: () => now, enrollmentStore }));
    const pairWith = (code: string, devicePublicKey: string) =>
      fetch(`${url}/oauth/pair`, { method: "POST", headers: { "content-type": "application/json" }, body: pairBody(code, devicePublicKey) });

    // Fingerprint mismatch: a code pre-bound to the approved device is refused
    // for any other device signing key and stays redeemable afterwards.
    const bound = enrollmentStore.issue({ nowMs: 1_000, ttlMs: 300_000, expectedDeviceFingerprint: approved.fingerprint });
    expect((await pairWith(bound.code, other.publicKeyPem)).status).toBe(403);
    expect((await pairWith(bound.code, approved.publicKeyPem)).status).toBe(201);

    // Used: the same code cannot shoulder a second pairing.
    expect((await pairWith(bound.code, approved.publicKeyPem)).status).toBe(403);

    // Expired: advancing past the code TTL fails closed.
    const expiring = enrollmentStore.issue({ nowMs: 1_000, ttlMs: 60_000, expectedDeviceFingerprint: approved.fingerprint });
    now = 61_000;
    expect((await pairWith(expiring.code, approved.publicKeyPem)).status).toBe(403);
  });
});
