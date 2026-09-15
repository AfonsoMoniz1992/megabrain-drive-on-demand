import { generateDeviceIdentity, type DeviceIdentity } from "./device-identity";
import { clearDeviceIdentity, type DeviceIdentitySecretStorage } from "./device-identity-store";

export interface LocalLeaseManager {
  clear(): void;
}

export interface LogoutDeviceSessionOptions {
  leaseManager: LocalLeaseManager;
  secretStorage: DeviceIdentitySecretStorage;
  persistClearedEnrollment: () => Promise<void>;
  clearCurrentAccessToken: () => void;
  createIdentity?: () => DeviceIdentity;
}

/**
 * Performs local logout only. It deliberately makes no broker request: a lost
 * device must be remotely revoked by an operator through the broker admin flow.
 */
export async function logoutDeviceSession(options: LogoutDeviceSessionOptions): Promise<DeviceIdentity> {
  options.leaseManager.clear();
  clearDeviceIdentity(options.secretStorage);
  await options.persistClearedEnrollment();
  options.clearCurrentAccessToken();
  return (options.createIdentity ?? generateDeviceIdentity)();
}
