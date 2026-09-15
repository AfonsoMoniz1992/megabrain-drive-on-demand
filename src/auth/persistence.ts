/**
 * Persistence guard for the mobile beta.
 *
 * Plugin data may persist only the broker base URL, non-secret enrollment state
 * and legacy cache fields. Device private identity belongs exclusively in
 * Obsidian SecretStorage. Google access tokens, refresh tokens, client secrets,
 * authorization codes, sealed leases, nonces and signature proofs must never
 * reach `saveData`. This module is the single allowlist that enforces that.
 */

import type { EnrollmentStatus } from "./lease-manager";

export const ALLOWED_PLUGIN_DATA_ROOT_KEYS = ["brokerBaseUrl", "allowedRootName", "enrollment", "driveRootId", "remoteFiles", "changesPageToken"] as const;
export const ALLOWED_ENROLLMENT_KEYS = ["pairId", "status", "expiresAtMs"] as const;

/** Secret-shaped key names that must never appear in plugin data. */
const FORBIDDEN_KEY_PATTERN = /^(access[_-]?token|refresh[_-]?token|id[_-]?token|token|client[_-]?secret|authorization[_-]?code|auth[_-]?code|code|sealed[_-]?lease|lease|proof|proof[_-]?message|nonce|device[_-]?code|session[_-]?key)$/i;

/** Google/JWT credential shapes that must never appear as a stored value. */
const FORBIDDEN_VALUE_PATTERNS: RegExp[] = [
  /ya29\./,
  /GOCSPX-/,
  /^1\/\/[0-9A-Za-z_-]{10,}$/,
  /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/
];

interface Violations {
  secrets: string[];
  unsupported: string[];
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function allowedKeysFor(path: string): readonly string[] | undefined {
  const last = path.split(".").at(-1) ?? "";
  if (path === "enrollment" || last === "enrollment") return ALLOWED_ENROLLMENT_KEYS;
  return undefined;
}

function scan(value: unknown, path: string, allowed: readonly string[] | undefined, out: Violations): void {
  if (typeof value === "string") {
    if (FORBIDDEN_VALUE_PATTERNS.some((pattern) => pattern.test(value))) out.secrets.push(path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => scan(item, path ? `${path}.${index}` : String(index), undefined, out));
    return;
  }
  if (!isPlainObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    const childPath = path ? `${path}.${key}` : key;
    if (FORBIDDEN_KEY_PATTERN.test(key)) out.secrets.push(childPath);
    else if (allowed && !allowed.includes(key)) out.unsupported.push(childPath);
    scan(child, childPath, allowedKeysFor(childPath), out);
  }
}

function collectViolations(value: unknown): Violations {
  const out: Violations = { secrets: [], unsupported: [] };
  scan(value, "", ALLOWED_PLUGIN_DATA_ROOT_KEYS, out);
  return out;
}

/** Paths of every non-persistable key or value, sorted for stable diagnostics. */
export function findForbiddenPersistence(value: unknown): string[] {
  const out = collectViolations(value);
  return [...out.secrets, ...out.unsupported].sort();
}

/**
 * Throws when plugin data would persist a Google/broker secret or an
 * unsupported key. Messages contain key paths only — never the values.
 */
export function assertPersistablePluginData(value: unknown): void {
  const out = collectViolations(value);
  if (out.secrets.length) throw new Error(`Plugin data must not persist Google or broker secrets: ${[...new Set(out.secrets)].sort().join(", ")}`);
  if (out.unsupported.length) throw new Error(`Plugin data contains an unsupported key: ${[...new Set(out.unsupported)].sort().join(", ")}`);
}

export interface PersistedMobileState {
  brokerBaseUrl: string;
  /** Operator-configured harmless root name sealed into leases; non-secret. */
  allowedRootName: string;
  enrollment: { pairId: string | null; status: "enrolled" | "not_enrolled"; expiresAtMs: number | null };
}

export interface LegacySettingsState {
  driveRootId?: string;
  remoteFiles?: unknown[];
  changesPageToken?: string;
}

/** Assembles the only plugin data shape the mobile beta is allowed to write. */
export function buildPersistedPluginData(input: PersistedMobileState & { legacy?: LegacySettingsState }): Record<string, unknown> {
  const data: Record<string, unknown> = {
    brokerBaseUrl: input.brokerBaseUrl,
    allowedRootName: input.allowedRootName,
    enrollment: { pairId: input.enrollment.pairId, status: input.enrollment.status, expiresAtMs: input.enrollment.expiresAtMs }
  };
  if (input.legacy) {
    if (input.legacy.driveRootId !== undefined) data.driveRootId = input.legacy.driveRootId;
    if (input.legacy.remoteFiles !== undefined) data.remoteFiles = input.legacy.remoteFiles;
    if (input.legacy.changesPageToken !== undefined) data.changesPageToken = input.legacy.changesPageToken;
  }
  assertPersistablePluginData(data);
  return data;
}

/**
 * Maps the live enrollment view onto the only enrollment state a beta build may
 * persist.
 *
 * A pairing that is still waiting for the browser approval is deliberately NOT
 * persisted: the pairing window is minutes long, so writing it as enrolled would
 * make the next session claim an authorisation that was never granted. Only a
 * pairing that actually received a lease is durable.
 */
export function toPersistedEnrollment(enrollment: {
  pairId: string | null;
  status: EnrollmentStatus;
  expiresAtMs: number | null;
}): PersistedMobileState["enrollment"] {
  if (enrollment.status === "enrolled" && enrollment.pairId) {
    return { pairId: enrollment.pairId, status: "enrolled", expiresAtMs: enrollment.expiresAtMs };
  }
  return { pairId: null, status: "not_enrolled", expiresAtMs: null };
}
