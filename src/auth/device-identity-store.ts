import {
  generateDeviceIdentity,
  restoreDeviceIdentity,
  serializeDeviceIdentity,
  type DeviceIdentity
} from "./device-identity";

/** Narrow adapter for Obsidian's local per-vault SecretStorage API. */
export interface DeviceIdentitySecretStorage {
  getSecret(id: string): string | null;
  setSecret(id: string, secret: string): void;
}

/** Lower-case SecretStorage identifier; bump only for an intentional format migration. */
export const DEVICE_IDENTITY_SECRET_ID = "obsidian-gdrive-streaming-device-identity-v1";

type SerializedDeviceIdentity = {
  ed25519PrivateKey: string;
  x25519PrivateKey: string;
};

function parseStoredIdentity(value: string | null): DeviceIdentity | null {
  if (!value) return null;
  try {
    const parsed: unknown = JSON.parse(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    const record = parsed as Record<string, unknown>;
    if (typeof record.ed25519PrivateKey !== "string" || typeof record.x25519PrivateKey !== "string") return null;
    return restoreDeviceIdentity({
      ed25519PrivateKey: record.ed25519PrivateKey,
      x25519PrivateKey: record.x25519PrivateKey
    });
  } catch {
    return null;
  }
}

/** Stores only the two serialized private keys under the fixed SecretStorage ID. */
export function saveDeviceIdentity(storage: DeviceIdentitySecretStorage, identity: DeviceIdentity): void {
  const serialized: SerializedDeviceIdentity = serializeDeviceIdentity(identity);
  storage.setSecret(DEVICE_IDENTITY_SECRET_ID, JSON.stringify(serialized));
}

/** Restores a valid identity, or creates and persists a replacement without logging stored values. */
export function loadOrCreateDeviceIdentity(storage: DeviceIdentitySecretStorage): DeviceIdentity {
  const restored = parseStoredIdentity(storage.getSecret(DEVICE_IDENTITY_SECRET_ID));
  if (restored) return restored;
  const identity = generateDeviceIdentity();
  saveDeviceIdentity(storage, identity);
  return identity;
}

/** SecretStorage has no deletion API; an empty value is treated as absent on subsequent loads. */
export function clearDeviceIdentity(storage: DeviceIdentitySecretStorage): void {
  storage.setSecret(DEVICE_IDENTITY_SECRET_ID, "");
}
