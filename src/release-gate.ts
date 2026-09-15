export interface DriveRuntimeStatus {
  enabled: false;
  cacheDeletionEnabled: false;
  reason: string;
}

/**
 * v0.1 is deliberately non-connectable. Drive transport code is retained only
 * as isolated, tested future primitives; the Obsidian entrypoint must not call it.
 */
export function driveRuntimeStatus(): DriveRuntimeStatus {
  return {
    enabled: false,
    cacheDeletionEnabled: false,
    reason: "Google Drive connection and cache deletion are not shipped in v0.1; no request or deletion was made."
  };
}

export interface DriveAccessInput {
  /** The device holds a paired, non-revoked enrollment. */
  enrolled: boolean;
  /** A device-bound lease is present and still usable without renewal. */
  hasValidLease: boolean;
}

export interface DriveAccessDecision {
  allowed: boolean;
  reason: string;
}

/**
 * The mobile beta's single hard gate in front of every Google Drive request:
 * no Drive call is permitted unless the device holds a valid enrollment *and* a
 * valid device-bound lease. Lease renewal itself goes only to the broker.
 */
export function driveAccessDecision(input: DriveAccessInput): DriveAccessDecision {
  if (!input.enrolled) {
    return { allowed: false, reason: "Not enrolled: no Google Drive request may be made before this device holds a valid lease." };
  }
  if (!input.hasValidLease) {
    return { allowed: false, reason: "No valid lease: renew the read-only lease before any Google Drive request." };
  }
  return { allowed: true, reason: "Device is enrolled with a valid read-only lease." };
}
