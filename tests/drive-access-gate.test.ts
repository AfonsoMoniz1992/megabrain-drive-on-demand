import { describe, expect, it } from "vitest";
import { driveAccessDecision } from "../src/release-gate";

describe("mobile beta drive access gate", () => {
  it("permits no Drive call before a valid enrollment and lease", () => {
    expect(driveAccessDecision({ enrolled: false, hasValidLease: false })).toEqual({
      allowed: false,
      reason: "Not enrolled: no Google Drive request may be made before this device holds a valid lease."
    });
  });

  it("still refuses when enrolled but the lease is missing or expired", () => {
    const decision = driveAccessDecision({ enrolled: true, hasValidLease: false });
    expect(decision.allowed).toBe(false);
    expect(decision.reason).toMatch(/lease/i);
  });

  it("allows Drive access only with both an enrollment and a valid lease", () => {
    expect(driveAccessDecision({ enrolled: true, hasValidLease: true })).toEqual({
      allowed: true,
      reason: "Device is enrolled with a valid read-only lease."
    });
  });
});
