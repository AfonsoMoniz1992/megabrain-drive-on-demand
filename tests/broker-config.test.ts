import { describe, expect, it } from "vitest";
import { parseBrokerRuntimeConfig } from "../broker/src/config";

const validConfig = {
  googleClientId: "test-client.apps.googleusercontent.com",
  googleCallbackUri: "https://broker.example.test/oauth/callback",
  googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
  pairingTtlMs: 300_000,
  pairingCapacity: 50,
  pairingRateLimitMaxAttempts: 3,
  pairingRateLimitWindowMs: 60_000
};

describe("broker runtime configuration", () => {
  it("rejects invalid or inherited OAuth and pairing configuration", () => {
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleClientId: "not-a-google-client" })).toThrow("Invalid googleClientId");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleCallbackUri: "http://broker.example.test/oauth/callback" })).toThrow("Invalid googleCallbackUri");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleCallbackUri: "https://broker.example.test/oauth/callback?debug=1" })).toThrow("Invalid googleCallbackUri");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleDriveScope: "https://www.googleapis.com/auth/drive" })).toThrow("Invalid googleDriveScope");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, pairingTtlMs: 0 })).toThrow("Invalid pairingTtlMs");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, pairingCapacity: 0 })).toThrow("Invalid pairingCapacity");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, pairingRateLimitMaxAttempts: 0 })).toThrow("Invalid pairingRateLimitMaxAttempts");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, pairingRateLimitWindowMs: 999 })).toThrow("Invalid pairingRateLimitWindowMs");
    expect(() => parseBrokerRuntimeConfig(Object.create(validConfig))).toThrow("Invalid googleClientId");
  });

  it("rejects callback URIs with an empty query or fragment delimiter", () => {
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleCallbackUri: "https://broker.example.test/oauth/callback?" })).toThrow("Invalid googleCallbackUri");
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleCallbackUri: "https://broker.example.test/oauth/callback#" })).toThrow("Invalid googleCallbackUri");
  });

  it.each([
    " https://broker.example.test/oauth/callback ",
    "https://broker.example.test/oauth/./callback"
  ])("rejects a noncanonical callback URI representation: %s", (googleCallbackUri) => {
    expect(() => parseBrokerRuntimeConfig({ ...validConfig, googleCallbackUri })).toThrow("Invalid googleCallbackUri");
  });

  it("parses an explicit non-secret OAuth and pairing configuration", () => {
    expect(parseBrokerRuntimeConfig(validConfig)).toEqual(validConfig);
  });
});
