import { describe, expect, it } from "vitest";
import { driveRuntimeStatus } from "../src/release-gate";

describe("v0.1 release gate", () => {
  it("hard-disables all live Google Drive activity", () => {
    const status = driveRuntimeStatus();
    expect(status.enabled).toBe(false);
    expect(status.cacheDeletionEnabled).toBe(false);
    expect(status.reason).toMatch(/not shipped/i);
  });
});
