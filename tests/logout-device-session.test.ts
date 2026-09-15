import { describe, expect, it } from "vitest";
import { generateDeviceIdentity, serializeDeviceIdentity } from "../src/auth/device-identity";
import { DEVICE_IDENTITY_SECRET_ID } from "../src/auth/device-identity-store";
import { logoutDeviceSession } from "../src/auth/logout-device-session";

describe("logout device session", () => {
  it("clears the lease, local identity and persisted enrollment before replacing in-memory identity", async () => {
    const calls: string[] = [];
    const secrets = new Map<string, string>([[DEVICE_IDENTITY_SECRET_ID, "old-private-identity"]]);
    const replacement = generateDeviceIdentity();

    const identity = await logoutDeviceSession({
      leaseManager: { clear: () => calls.push("lease.clear") },
      secretStorage: {
        getSecret: (id) => secrets.get(id) ?? null,
        setSecret: (id, value) => { secrets.set(id, value); calls.push(`secret.set:${value}`); }
      },
      persistClearedEnrollment: async () => { calls.push("saveData:not_enrolled"); },
      clearCurrentAccessToken: () => calls.push("access-token.clear"),
      createIdentity: () => { calls.push("identity.generate"); return replacement; }
    });

    expect(calls).toEqual([
      "lease.clear",
      "secret.set:",
      "saveData:not_enrolled",
      "access-token.clear",
      "identity.generate"
    ]);
    expect(secrets.get(DEVICE_IDENTITY_SECRET_ID)).toBe("");
    expect(serializeDeviceIdentity(identity)).toEqual(serializeDeviceIdentity(replacement));
  });
});
