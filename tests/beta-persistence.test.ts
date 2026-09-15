import { describe, expect, it } from "vitest";
import { BrokerClient } from "../src/auth/broker-client";
import { generateDeviceIdentity, sealLeaseEnvelope, serializeDeviceIdentity } from "../src/auth/device-identity";
import { LeaseManager } from "../src/auth/lease-manager";
import {
  ALLOWED_PLUGIN_DATA_ROOT_KEYS,
  assertPersistablePluginData,
  buildPersistedPluginData,
  findForbiddenPersistence,
  toPersistedEnrollment
} from "../src/auth/persistence";

const BASE_URL = "https://broker.example.test/gdrive-stream-oauth";
const GOOGLE_ACCESS_TOKEN = "ya29.super-secret-google-token";
const REFRESH_TOKEN = "1//0eXAMPLErefreshTokenValue";
const CLIENT_SECRET = "GOCSPX-example-client-secret";
const JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.signature-value";

describe("mobile beta persistence guard", () => {
  it("never persists a pairing that is still waiting for consent", () => {
    // The pairing window is minutes long, so a pending pairing must not survive
    // a restart as an authorisation that was never granted.
    expect(toPersistedEnrollment({ pairId: "b".repeat(64), status: "awaiting_consent", expiresAtMs: 1_060_000 })).toEqual({
      pairId: null,
      status: "not_enrolled",
      expiresAtMs: null
    });
    expect(toPersistedEnrollment({ pairId: "b".repeat(64), status: "enrolled", expiresAtMs: 5 })).toEqual({
      pairId: "b".repeat(64),
      status: "enrolled",
      expiresAtMs: 5
    });
    expect(toPersistedEnrollment({ pairId: null, status: "not_enrolled", expiresAtMs: null })).toEqual({
      pairId: null,
      status: "not_enrolled",
      expiresAtMs: null
    });
  });

  it("allowlists only non-secret mobile beta state", () => {
    expect([...ALLOWED_PLUGIN_DATA_ROOT_KEYS].sort()).toEqual(["allowedRootName", "brokerBaseUrl", "changesPageToken", "driveRootId", "enrollment", "remoteFiles"]);
  });

  it("builds a persistable payload with exactly the mobile sections", () => {
    const identity = generateDeviceIdentity();
    const serializedIdentity = serializeDeviceIdentity(identity);
    const data = buildPersistedPluginData({
      brokerBaseUrl: BASE_URL,
      allowedRootName: "operator-test-root",
      enrollment: { pairId: "b".repeat(64), status: "enrolled", expiresAtMs: 1_700_000_000_000 }
    });
    expect(Object.keys(data).sort()).toEqual(["allowedRootName", "brokerBaseUrl", "enrollment"]);
    expect(Object.keys(data.enrollment as object).sort()).toEqual(["expiresAtMs", "pairId", "status"]);
    const persisted = JSON.stringify(data);
    expect(persisted).not.toContain(serializedIdentity.ed25519PrivateKey);
    expect(persisted).not.toContain(serializedIdentity.x25519PrivateKey);
    expect(persisted).not.toContain("deviceIdentity");
    expect(findForbiddenPersistence(data)).toEqual([]);
  });

  it("rejects Google access, refresh and client-secret material anywhere in the tree", () => {
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, accessToken: GOOGLE_ACCESS_TOKEN })).toThrow(/must not persist/i);
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, enrollment: { pairId: "x", refreshToken: REFRESH_TOKEN } })).toThrow(/must not persist/i);
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, device: { clientSecret: CLIENT_SECRET } })).toThrow(/must not persist/i);
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, notes: [{ value: JWT }] })).toThrow(/must not persist/i);
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, enrollment: { pairId: "x", sealedLease: "envelope" } })).toThrow(/must not persist/i);
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, authorizationCode: "4/0AeanS" })).toThrow(/must not persist/i);
  });

  it("refuses unknown keys such as the one-time enrollment code", () => {
    expect(() => assertPersistablePluginData({ brokerBaseUrl: BASE_URL, enrollmentCode: "ENROLL-1234" })).toThrow(/unsupported key/i);
    expect(findForbiddenPersistence({ brokerBaseUrl: BASE_URL, enrollmentCode: "ENROLL-1234" })).toEqual(["enrollmentCode"]);
  });

  it("rejects legacy plaintext device identities rather than carrying them forward", () => {
    const identity = serializeDeviceIdentity(generateDeviceIdentity());
    const legacy = { brokerBaseUrl: BASE_URL, deviceIdentity: identity };

    expect(() => assertPersistablePluginData(legacy)).toThrow(/unsupported key/i);
    expect(findForbiddenPersistence(legacy)).toEqual(["deviceIdentity"]);
  });

  it("persists only enrollment state after a real enrollment and lease", async () => {
    const identity = generateDeviceIdentity();
    const saved: unknown[] = [];
    const store = { async save(data: unknown): Promise<void> { saved.push(JSON.parse(JSON.stringify(data)) as unknown); } };
    const manager = new LeaseManager({
      broker: new BrokerClient({
        baseUrl: BASE_URL,
        request: async (request) => {
          if (request.url.endsWith("/oauth/pair")) {
            return { status: 201, json: { pairId: "d".repeat(64), oauthState: "s", proofMessage: "proof", expiresAtMs: 9_999_999, authorizationUrl: "https://accounts.google.com/o/oauth2/v2/auth" } };
          }
          return { status: 200, json: { sealedLease: sealLeaseEnvelope(identity.x25519PublicKey, { accessToken: GOOGLE_ACCESS_TOKEN, expiresAtMs: 9_999_999, scope: "drive.readonly", allowedRootName: "example-test-root" }), expiresAtMs: 9_999_999 } };
        }
      }),
      identity,
      openAuthorizationUrl: () => undefined,
      now: () => 1_000_000,
      sleep: async () => undefined
    });

    await manager.enroll("ENROLL-1234");
    await expect(manager.getValidAccessToken()).resolves.toBe(GOOGLE_ACCESS_TOKEN);

    await store.save(buildPersistedPluginData({
      brokerBaseUrl: BASE_URL,
      allowedRootName: "example-test-root",
      enrollment: { pairId: manager.enrollment.pairId, status: "enrolled", expiresAtMs: manager.enrollment.expiresAtMs }
    }));

    const serialized = JSON.stringify(saved);
    expect(serialized).not.toContain("ya29");
    expect(serialized).not.toContain("super-secret");
    expect(serialized).not.toContain("accessToken");
    expect(serialized).not.toContain("ENROLL-1234");
    expect(serialized).not.toContain(serializeDeviceIdentity(identity).ed25519PrivateKey);
    expect(serialized).not.toContain(serializeDeviceIdentity(identity).x25519PrivateKey);
    expect(Object.keys(saved[0] as object).sort()).toEqual(["allowedRootName", "brokerBaseUrl", "enrollment"]);
    expect(() => assertPersistablePluginData(saved[0])).not.toThrow();
  });
});
