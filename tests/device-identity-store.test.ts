import { describe, expect, it, vi } from "vitest";
import { serializeDeviceIdentity } from "../src/auth/device-identity";
import {
  DEVICE_IDENTITY_SECRET_ID,
  clearDeviceIdentity,
  loadOrCreateDeviceIdentity,
  saveDeviceIdentity
} from "../src/auth/device-identity-store";

class MemorySecretStorage {
  readonly values = new Map<string, string>();

  getSecret(id: string): string | null {
    return this.values.get(id) ?? null;
  }

  setSecret(id: string, secret: string): void {
    this.values.set(id, secret);
  }
}

describe("device identity SecretStorage", () => {
  it("creates and saves an identity when no SecretStorage value exists", () => {
    const storage = new MemorySecretStorage();

    const identity = loadOrCreateDeviceIdentity(storage);

    expect(storage.getSecret(DEVICE_IDENTITY_SECRET_ID)).toBe(JSON.stringify(serializeDeviceIdentity(identity)));
  });

  it("saves an identity as only the serializable private-key JSON", () => {
    const storage = new MemorySecretStorage();
    const identity = loadOrCreateDeviceIdentity(storage);
    storage.values.clear();

    saveDeviceIdentity(storage, identity);

    expect(storage.getSecret(DEVICE_IDENTITY_SECRET_ID)).toBe(JSON.stringify(serializeDeviceIdentity(identity)));
  });

  it("restores exactly the identity saved under the fixed SecretStorage ID", () => {
    const storage = new MemorySecretStorage();
    const original = loadOrCreateDeviceIdentity(storage);

    const restored = loadOrCreateDeviceIdentity(storage);

    expect(serializeDeviceIdentity(restored)).toEqual(serializeDeviceIdentity(original));
  });

  it("replaces malformed or empty values with a fresh identity without logging", () => {
    const storage = new MemorySecretStorage();
    const error = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    storage.setSecret(DEVICE_IDENTITY_SECRET_ID, "not JSON");

    const malformedReplacement = loadOrCreateDeviceIdentity(storage);
    storage.setSecret(DEVICE_IDENTITY_SECRET_ID, "");
    const emptyReplacement = loadOrCreateDeviceIdentity(storage);

    expect(JSON.parse(storage.getSecret(DEVICE_IDENTITY_SECRET_ID) ?? "null")).toEqual(serializeDeviceIdentity(emptyReplacement));
    expect(serializeDeviceIdentity(malformedReplacement)).not.toEqual(serializeDeviceIdentity(emptyReplacement));
    expect(error).not.toHaveBeenCalled();
    expect(warn).not.toHaveBeenCalled();
  });

  it("clears the SecretStorage value so a future load generates a new identity", () => {
    const storage = new MemorySecretStorage();
    const original = loadOrCreateDeviceIdentity(storage);

    clearDeviceIdentity(storage);

    expect(storage.getSecret(DEVICE_IDENTITY_SECRET_ID)).toBe("");
    const replacement = loadOrCreateDeviceIdentity(storage);
    expect(serializeDeviceIdentity(replacement)).not.toEqual(serializeDeviceIdentity(original));
  });
});
