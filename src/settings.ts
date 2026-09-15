import type { RemoteFile } from "./core/remote-index";
import { validateBrokerBaseUrl } from "./auth/mobile-pairing";

/**
 * Plugin settings for the mobile beta.
 *
 * `brokerBaseUrl` is the only network destination the plugin may talk to; it is
 * persisted because it is not a secret. `enrollmentCode` is a one-time pairing
 * code typed by the user: it lives only in memory, is cleared after a
 * successful enrollment, and is explicitly excluded from `toPersistedSettings`.
 * Access tokens, refresh tokens, client secrets and authorization codes never
 * appear in this type at all — they are not persistable by construction.
 */

export interface GDriveStreamingSettings {
  driveRootId: string;
  changesPageToken?: string;
  remoteFiles: RemoteFile[];
  brokerBaseUrl: string;
  /** Operator-configured Drive folder name the broker sealed into leases. */
  allowedRootName: string;
  /** Transient pairing code. Never written to plugin data. */
  enrollmentCode: string;
}

/**
 * A broker is operator configuration, never a personal deployment default.
 * The invalid-reserved hostname is used only inside the runtime constructor so
 * an unconfigured plugin can open its settings without making any request.
 */
export const DEFAULT_BROKER_BASE_URL = "";
export const UNCONFIGURED_BROKER_BASE_URL = "https://broker.invalid";

export function brokerBaseUrlForRuntime(value: string): string {
  return value.trim() === "" ? UNCONFIGURED_BROKER_BASE_URL : validateBrokerBaseUrl(value);
}

/**
 * A Drive folder name that cannot exist, used only while the operator has not
 * configured their own root. Resolution then fails closed with a "not found"
 * error instead of browsing whatever folder happens to be named like a
 * maintainer default.
 */
export const UNCONFIGURED_ROOT_NAME = "__gdrive-stream-root-not-configured__";

export function allowedRootNameForRuntime(value: string): string {
  const normalized = normalizeAllowedRootName(value);
  return normalized === "" ? UNCONFIGURED_ROOT_NAME : normalized;
}

export const DEFAULT_SETTINGS: GDriveStreamingSettings = {
  driveRootId: "",
  remoteFiles: [],
  brokerBaseUrl: DEFAULT_BROKER_BASE_URL,
  allowedRootName: "",
  enrollmentCode: ""
};

/**
 * Settings keys that may be written through `saveData`. Every entry is also on
 * `ALLOWED_PLUGIN_DATA_ROOT_KEYS`; `enrollmentCode` is deliberately absent.
 */
export const PERSISTED_SETTING_KEYS = ["brokerBaseUrl", "allowedRootName", "changesPageToken", "driveRootId", "remoteFiles"] as const;

/**
 * Normalises an operator-supplied Drive folder name. It must be a single folder
 * name — not a path, not a traversal, not a control sequence — because it is
 * compared byte-for-byte with the root the broker seals into each lease.
 * Invalid input is cleared so a mistyped value fails loudly at enrolment
 * instead of silently targeting a different folder.
 */
export function normalizeAllowedRootName(value: string): string {
  const trimmed = value.trim();
  if (trimmed === "") return "";
  if (trimmed.length > 256) return "";
  if (/[\u0000-\u001f]/.test(trimmed)) return "";
  if (trimmed.includes("/") || trimmed.includes("\\")) return "";
  if (trimmed === "." || trimmed === "..") return "";
  return trimmed;
}

/**
 * Normalises a stored/typed broker URL. A hostile or malformed value (plain
 * HTTP, credentials, traversal) never becomes the persisted broker origin; the
 * default is deliberately an empty value: no operator should silently target
 * another person's broker. Invalid input is cleared instead of substituted.
 */
export function normalizeBrokerBaseUrl(value: string): string {
  if (value.trim() === "") return "";
  try {
    return validateBrokerBaseUrl(value);
  } catch {
    return "";
  }
}

/**
 * Projects settings onto the persistable subset. Throws for a malformed broker
 * URL rather than silently persisting an unusable destination, and never emits
 * the transient enrollment code.
 */
export function toPersistedSettings(settings: GDriveStreamingSettings): Record<string, unknown> {
  const configured = settings.brokerBaseUrl.trim();
  const brokerBaseUrl = configured === "" ? "" : validateBrokerBaseUrl(configured);
  const persisted: Record<string, unknown> = {
    brokerBaseUrl,
    allowedRootName: normalizeAllowedRootName(settings.allowedRootName),
    driveRootId: settings.driveRootId,
    remoteFiles: settings.remoteFiles
  };
  if (settings.changesPageToken !== undefined) persisted.changesPageToken = settings.changesPageToken;
  return persisted;
}
