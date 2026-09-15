import { generateKeyPairSync, sign } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { GOOGLE_DRIVE_READONLY_SCOPE, parseBrokerRuntimeConfig } from "../broker/src/config";
import { EnrollmentStore, deviceSigningKeyFingerprint } from "../broker/src/enrollment-store";
import {
  deriveEnrollmentStoreKey,
  EncryptedEnrollmentRecordStore
} from "../broker/src/enrollment-record-store";
import type { OAuthTokenTransport } from "../broker/src/google-oauth-client";
import { unsealLease, type SealedLease } from "../broker/src/lease-sealer";
import { PairingStore } from "../broker/src/pairing-store";
import { deriveRefreshTokenStoreKey, EncryptedRefreshTokenStore } from "../broker/src/refresh-token-store";
// The broker requires an explicit allowed root; tests name a harmless one.
import { createTestBrokerServer as createBrokerServer } from "./support/broker-server";

const CALLBACK_URI = "https://broker.example.test/oauth/google/callback";
const CALLBACK_PATH = "/oauth/google/callback";
const CLIENT_SECRET = "test-client-secret-must-not-leak";
const REFRESH_TOKEN = "1//0g-refresh-token-must-not-leak";
const REFRESHED_ACCESS_TOKEN = "ya29.refreshed-access-token-must-stay-sealed";
const CODE = "test-authorization-code-must-not-leak";
const MASTER_KEY = Buffer.alloc(32, 7);

type Server = ReturnType<typeof createBrokerServer>;

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function ed25519Device() {
  const keys = generateKeyPairSync("ed25519");
  const publicKeyPem = keys.publicKey.export({ type: "spki", format: "pem" }).toString();
  return {
    publicKeyPem,
    fingerprint: deviceSigningKeyFingerprint(publicKeyPem),
    sign: (data: Buffer) => sign(null, data, keys.privateKey).toString("base64url")
  };
}

function x25519Device() {
  const keys = generateKeyPairSync("x25519");
  return {
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }).toString(),
    privateKeyPem: keys.privateKey.export({ type: "pkcs8", format: "pem" }).toString()
  };
}

function transport(): OAuthTokenTransport {
  return async (request) => {
    const params = new URLSearchParams(request.body);
    if (params.get("grant_type") === "authorization_code") {
      return {
        status: 200,
        body: JSON.stringify({
          access_token: "ya29.callback-access-token",
          token_type: "Bearer",
          refresh_token: REFRESH_TOKEN,
          expires_in: 3_600,
          scope: GOOGLE_DRIVE_READONLY_SCOPE
        })
      };
    }
    return {
      status: 200,
      body: JSON.stringify({
        access_token: REFRESHED_ACCESS_TOKEN,
        token_type: "Bearer",
        expires_in: 3_600,
        scope: GOOGLE_DRIVE_READONLY_SCOPE
      })
    };
  };
}

interface Runtime {
  baseUrl: string;
  pairingStore: PairingStore;
  enrollmentStore: EnrollmentStore;
  enrollmentRecords: EncryptedEnrollmentRecordStore;
}

/** Starts a broker "process": a fresh in-memory pairing store over a durable file-backed enrollment store. */
async function startRuntime(input: {
  directory: string;
  now: () => number;
  records: EncryptedEnrollmentRecordStore;
  refreshTokens: EncryptedRefreshTokenStore;
}): Promise<Runtime> {
  const pairingStore = new PairingStore();
  const enrollmentStore = new EnrollmentStore();
  const server = createBrokerServer({
    now: input.now,
    pairingStore,
    enrollmentStore,
    enrollmentRecordStore: input.records,
    refreshTokenStore: input.refreshTokens,
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
    oauthTransport: transport()
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server address missing");
  return { baseUrl: `http://127.0.0.1:${address.port}`, pairingStore, enrollmentStore, enrollmentRecords: input.records };
}

function post(runtime: Runtime, path: string, body: object): Promise<Response> {
  return fetch(`${runtime.baseUrl}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
}

describe("durable device enrollment and lease renewal", () => {
  it("renews a sealed lease after a broker restart and long after the pairing TTL", async () => {
    const directory = mkdtempSync(join(tmpdir(), "mben-durable-"));
    directories.push(directory);
    const recordsPath = join(directory, "protected", "enrollments.bin");
    const refreshPath = join(directory, "protected", "refresh-token.bin");
    const records = new EncryptedEnrollmentRecordStore(recordsPath, deriveEnrollmentStoreKey(MASTER_KEY));
    const refreshTokens = new EncryptedRefreshTokenStore(refreshPath, deriveRefreshTokenStoreKey(MASTER_KEY));

    let nowMs = 1_000;
    const device = ed25519Device();
    const encryption = x25519Device();

    // --- Broker run #1: pair, complete OAuth, claim the first sealed lease ---
    const first = await startRuntime({ directory, now: () => nowMs, records, refreshTokens });
    const { code } = first.enrollmentStore.issue({
      nowMs,
      ttlMs: 300_000,
      expectedDeviceFingerprint: device.fingerprint
    });
    const paired = await post(first, "/oauth/pair", {
      devicePublicKeyPem: device.publicKeyPem,
      deviceEncryptionPublicKeyPem: encryption.publicKeyPem,
      enrollmentCode: code
    });
    expect(paired.status).toBe(201);
    const pairing = (await paired.json()) as { pairId: string; oauthState: string; proofMessage: string };

    const callbacks = await fetch(
      `${first.baseUrl}${CALLBACK_PATH}?${new URLSearchParams({ state: pairing.oauthState, code: CODE }).toString()}`
    );
    expect(callbacks.status).toBe(200);

    const claimed = await post(first, "/oauth/claim", {
      pairId: pairing.pairId,
      proof: device.sign(Buffer.from(pairing.proofMessage))
    });
    expect(claimed.status).toBe(200);

    // The enrollment is now durable and the record is encrypted at rest.
    const stored = await records.find(pairing.pairId);
    expect(stored).toMatchObject({
      deviceSigningPublicKeyPem: device.publicKeyPem,
      deviceEncryptionPublicKeyPem: encryption.publicKeyPem,
      revoked: false
    });
    expect(stored!.expiresAtMs).toBeGreaterThan(nowMs);
    expect(statSync(recordsPath).mode & 0o777).toBe(0o600);
    expect(statSync(join(directory, "protected")).mode & 0o777).toBe(0o700);
    const persisted = readFileSync(recordsPath, "utf8");
    expect(persisted).not.toContain(device.publicKeyPem);
    expect(persisted).not.toContain(encryption.publicKeyPem);

    // A nonce issued by run #1 is ephemeral and must not survive the restart.
    const beforeRestart = (await (await post(first, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };

    // --- Broker run #2: a fresh process with a fresh pairing store, same durable files ---
    nowMs = 1_000 + 20 * 60_000; // well past the 5-minute pairing TTL
    const restartedRecords = new EncryptedEnrollmentRecordStore(recordsPath, deriveEnrollmentStoreKey(MASTER_KEY));
    const restartedRefresh = new EncryptedRefreshTokenStore(refreshPath, deriveRefreshTokenStoreKey(MASTER_KEY));
    const second = await startRuntime({ directory, now: () => nowMs, records: restartedRecords, refreshTokens: restartedRefresh });

    // The pairing handshake memory is gone, so a stale nonce fails closed...
    const stale = await post(second, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce: beforeRestart.nonce,
      proof: device.sign(Buffer.from(beforeRestart.nonce, "base64url"))
    });
    expect(stale.status).toBe(403);
    expect(await stale.json()).toEqual({ error: "invalid_nonce" });

    // ...but the durable enrollment still authorizes a fresh renewal.
    const nonceResponse = await post(second, "/oauth/nonce", { pairId: pairing.pairId });
    expect(nonceResponse.status).toBe(200);
    const { nonce } = (await nonceResponse.json()) as { nonce: string };

    const lease = await post(second, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce,
      proof: device.sign(Buffer.from(nonce, "base64url"))
    });
    expect(lease.status).toBe(200);
    const leaseBody = (await lease.json()) as { sealedLease: SealedLease; expiresAtMs: number };
    const payload = unsealLease({
      envelope: leaseBody.sealedLease,
      deviceEncryptionPrivateKeyPem: encryption.privateKeyPem
    }) as { accessToken: string; allowedRootName: string };
    expect(payload.accessToken).toBe(REFRESHED_ACCESS_TOKEN);
    expect(payload.allowedRootName).toBe("example-test-root");

    // An never-enrolled pairing is refused by the durable store.
    const unknown = await post(second, "/oauth/nonce", { pairId: "0".repeat(64) });
    expect(unknown.status).toBe(403);
    expect(await unknown.json()).toEqual({ error: "revoked" });

    // A wrong signing key is refused even though the pairId is enrolled.
    const attacker = ed25519Device();
    const forgedNonce = (await (await post(second, "/oauth/nonce", { pairId: pairing.pairId })).json()) as { nonce: string };
    const forged = await post(second, "/oauth/lease", {
      pairId: pairing.pairId,
      nonce: forgedNonce.nonce,
      proof: attacker.sign(Buffer.from(forgedNonce.nonce, "base64url"))
    });
    expect(forged.status).toBe(403);
    expect(await forged.json()).toEqual({ error: "invalid_proof" });

    // Durable revocation stops further renewals for every future process.
    expect(await restartedRecords.revoke(pairing.pairId)).toBe(true);
    const revokedNonce = await post(second, "/oauth/nonce", { pairId: pairing.pairId });
    expect(revokedNonce.status).toBe(403);
    expect(await revokedNonce.json()).toEqual({ error: "revoked" });
  });
});
