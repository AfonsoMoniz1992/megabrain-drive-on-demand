export const GOOGLE_DRIVE_READONLY_SCOPE = "https://www.googleapis.com/auth/drive.readonly";

export interface BrokerRuntimeConfig {
  googleClientId: string;
  googleCallbackUri: string;
  googleDriveScope: typeof GOOGLE_DRIVE_READONLY_SCOPE;
  pairingTtlMs: number;
  pairingCapacity: number;
  pairingRateLimitMaxAttempts: number;
  pairingRateLimitWindowMs: number;
}

function readString(input: Record<string, unknown>, key: string): string {
  const value = input[key];
  if (!Object.hasOwn(input, key) || typeof value !== "string" || value.length === 0) throw new Error(`Invalid ${key}`);
  return value;
}

function readInteger(input: Record<string, unknown>, key: string, minimum: number, maximum: number): number {
  const value = input[key];
  if (!Object.hasOwn(input, key) || !Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new Error(`Invalid ${key}`);
  return value as number;
}

function validateCallbackUri(value: string): string {
  let callback: URL;
  try { callback = new URL(value); } catch { throw new Error("Invalid googleCallbackUri"); }
  if (callback.href !== value || callback.protocol !== "https:" || callback.username || callback.password || value.includes("?") || value.includes("#")) {
    throw new Error("Invalid googleCallbackUri");
  }
  return value;
}

/** Parses explicitly supplied non-secret broker configuration. */
export function parseBrokerRuntimeConfig(input: Record<string, unknown>): BrokerRuntimeConfig {
  const googleClientId = readString(input, "googleClientId");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]*\.apps\.googleusercontent\.com$/.test(googleClientId)) {
    throw new Error("Invalid googleClientId");
  }
  const googleCallbackUri = validateCallbackUri(readString(input, "googleCallbackUri"));
  const googleDriveScope = readString(input, "googleDriveScope");
  if (googleDriveScope !== GOOGLE_DRIVE_READONLY_SCOPE) throw new Error("Invalid googleDriveScope");

  return {
    googleClientId,
    googleCallbackUri,
    googleDriveScope: GOOGLE_DRIVE_READONLY_SCOPE,
    pairingTtlMs: readInteger(input, "pairingTtlMs", 1_000, 10 * 60_000),
    pairingCapacity: readInteger(input, "pairingCapacity", 1, 10_000),
    pairingRateLimitMaxAttempts: readInteger(input, "pairingRateLimitMaxAttempts", 1, 100),
    pairingRateLimitWindowMs: readInteger(input, "pairingRateLimitWindowMs", 1_000, 60 * 60_000)
  };
}
