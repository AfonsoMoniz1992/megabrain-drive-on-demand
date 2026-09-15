import { describe, expect, it } from "vitest";
import { createPairingChallenge, isClaimablePairing, validateBrokerUrl, validatePairId } from "../src/auth/mobile-pairing";

describe("mobile pairing protocol", () => {
  const pairId = "a".repeat(64);
  const deviceKey = "A".repeat(43);

  it("accepts only a fixed clean HTTPS broker origin", () => {
    expect(validateBrokerUrl("https://oauth.broker.example")).toBe("https://oauth.broker.example");
    expect(() => validateBrokerUrl("http://oauth.broker.example")).toThrow(/https/i);
    expect(() => validateBrokerUrl("https://user:pass@oauth.broker.example")).toThrow(/credentials/i);
    expect(() => validateBrokerUrl("https://oauth.broker.example/callback?code=x")).toThrow(/origin/i);
  });

  it("requires a 256-bit pairing ID", () => {
    expect(validatePairId(pairId)).toBe(pairId);
    expect(() => validatePairId("abc")).toThrow(/256-bit/i);
  });

  it("binds a challenge to one device key and expiry", () => {
    const challenge = createPairingChallenge({ pairId, devicePublicKey: deviceKey, nowMs: 1_000, ttlMs: 60_000 });
    expect(isClaimablePairing(challenge, { pairId, devicePublicKey: deviceKey, nowMs: 60_999 })).toBe(true);
    expect(isClaimablePairing(challenge, { pairId, devicePublicKey: "B".repeat(43), nowMs: 2_000 })).toBe(false);
    expect(isClaimablePairing(challenge, { pairId, devicePublicKey: deviceKey, nowMs: 61_000 })).toBe(false);
  });
});
