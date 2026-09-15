import { lstat, readFile } from "node:fs/promises";
import {
  GOOGLE_DRIVE_READONLY_SCOPE,
  parseBrokerRuntimeConfig,
  type BrokerRuntimeConfig
} from "./config.js";

/**
 * Protected secret-file loading for the broker entrypoint.
 *
 * Threat model: the operator injects the OAuth client secret, the admin bearer
 * token and the 32-byte master key as *files* rather than as environment
 * values, so they never appear in `ps`, in an environment dump or in a shell
 * history. Each file is therefore rejected unless it is a regular file, owned
 * by the service uid and inaccessible to group and other (no bits outside
 * 0600). Reading is the only operation performed: nothing is created, nothing
 * is chmodded, nothing is logged.
 *
 * Every failure is a typed RuntimeSecretError carrying a fixed message that
 * names the *path* or the *environment variable* but never the secret value.
 */

export type RuntimeSecretErrorCode =
  | "not_configured"
  | "missing_file"
  | "not_regular_file"
  | "not_owned"
  | "insecure_permissions"
  | "empty_secret"
  | "invalid_base64"
  | "invalid_key_length"
  | "io_error";

/** Typed failure. Messages are fixed strings and never carry secret material. */
export class RuntimeSecretError extends Error {
  readonly code: RuntimeSecretErrorCode;

  constructor(code: RuntimeSecretErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "RuntimeSecretError";
    this.code = code;
  }
}

export const TOKEN_KEY_BYTES = 32;

const BASE64_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const DEFAULT_PUBLIC_PORT = 34_003;
const DEFAULT_ADMIN_PORT = 34_004;
const DEFAULT_GATEWAY_PORT = 34_005;
const DEFAULT_PRIVATE_GATEWAY_PORT = 34_006;
const MIN_PORT = 1_024;
const MAX_PORT = 65_535;
/** Mirrors the admin server's own floor, so a weak token fails at startup not at first request. */
const MIN_ADMIN_TOKEN_LENGTH = 16;

const notConfigured = (message: string): RuntimeSecretError =>
  new RuntimeSecretError("not_configured", message);

/** Test seams: inject the account ids expected in the deployment policy. */
export interface ProtectedFileOptions {
  uid?: number;
  gid?: number;
  /** Defaults to UID 0; a root-owned credential must be readable only by this service group. */
  rootUid?: number;
}

function serviceUid(options?: ProtectedFileOptions): number {
  if (options?.uid !== undefined) return options.uid;
  return typeof process.getuid === "function" ? process.getuid() : -1;
}

function serviceGid(options?: ProtectedFileOptions): number {
  if (options?.gid !== undefined) return options.gid;
  return typeof process.getgid === "function" ? process.getgid() : -1;
}

function trustedRootUid(options?: ProtectedFileOptions): number {
  return options?.rootUid ?? 0;
}

function isMissingPath(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as NodeJS.ErrnoException).code === "ENOENT";
}

/**
 * Reads a secret file after proving it is a regular file, owned by the service
 * uid and closed to group/other. `lstat` (not `stat`) is used deliberately so a
 * symlink is refused rather than followed out of the protected directory.
 */
async function readProtectedText(label: string, filePath: string, options?: ProtectedFileOptions): Promise<string> {
  if (typeof filePath !== "string" || filePath.trim().length === 0) {
    throw notConfigured(`${label} path is required`);
  }

  let stats;
  try {
    stats = await lstat(filePath);
  } catch (error) {
    if (isMissingPath(error)) {
      throw new RuntimeSecretError("missing_file", `${label} file is missing: ${filePath}`, { cause: error });
    }
    throw new RuntimeSecretError("io_error", `${label} file could not be inspected: ${filePath}`, { cause: error });
  }

  if (!stats.isFile()) {
    throw new RuntimeSecretError("not_regular_file", `${label} path is not a regular file: ${filePath}`);
  }

  const uid = serviceUid(options);
  const gid = serviceGid(options);
  const serviceOwned = uid < 0 || stats.uid === uid;
  const rootControlled =
    uid >= 0 &&
    stats.uid === trustedRootUid(options) &&
    gid >= 0 &&
    stats.gid === gid &&
    // Group gets read-only access; no group execute/write or any other access.
    (stats.mode & 0o027) === 0 &&
    (stats.mode & 0o040) === 0o040;

  if (!serviceOwned && !rootControlled) {
    throw new RuntimeSecretError(
      "not_owned",
      `${label} file is not owned by the service or trusted root/service group: ${filePath}`
    );
  }

  if (serviceOwned && (stats.mode & 0o077) !== 0) {
    throw new RuntimeSecretError(
      "insecure_permissions",
      `${label} file must not be accessible to group or other (expected mode 0600): ${filePath}`
    );
  }

  if (rootControlled && (stats.mode & 0o027) !== 0) {
    throw new RuntimeSecretError(
      "insecure_permissions",
      `${label} root-owned file must be group-read-only for the service (expected mode 0640): ${filePath}`
    );
  }

  let raw: string;
  try {
    raw = await readFile(filePath, "utf8");
  } catch (error) {
    throw new RuntimeSecretError("io_error", `${label} file could not be read: ${filePath}`, { cause: error });
  }
  return raw.trim();
}

/** Reads a UTF-8 secret (client secret, admin token) and trims trailing newlines. */
export async function readProtectedSecretFile(
  filePath: string,
  options?: ProtectedFileOptions
): Promise<string> {
  const value = await readProtectedText("Secret", filePath, options);
  if (value.length === 0) {
    throw new RuntimeSecretError("empty_secret", `Secret file is empty: ${filePath}`);
  }
  return value;
}

/**
 * Reads a base64-encoded 32-byte master key. Both padded and unpadded base64 are
 * accepted; anything that is not canonical base64 is refused as invalid rather
 * than silently trimmed, and a wrong length is a typed failure.
 */
export async function readProtectedKeyFile(
  filePath: string,
  options?: ProtectedFileOptions
): Promise<Buffer> {
  const value = await readProtectedText("Token key", filePath, options);
  if (!BASE64_PATTERN.test(value)) {
    throw new RuntimeSecretError("invalid_base64", `Token key file is not valid base64: ${filePath}`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64").replace(/=+$/, "") !== value.replace(/=+$/, "")) {
    throw new RuntimeSecretError("invalid_base64", `Token key file is not valid base64: ${filePath}`);
  }
  if (decoded.length !== TOKEN_KEY_BYTES) {
    throw new RuntimeSecretError(
      "invalid_key_length",
      `Token key file must decode to exactly ${TOKEN_KEY_BYTES} bytes: ${filePath}`
    );
  }
  return decoded;
}

/** Everything the entrypoint needs, with secrets already loaded from protected files. */
export interface BrokerRuntimeEnvironment {
  /** Validated non-secret OAuth and pairing configuration. */
  config: BrokerRuntimeConfig;
  clientSecret: string;
  adminToken: string;
  tokenKey: Buffer;
  /** Unique root name sealed into device leases; defaults for backward-compatible beta deployments. */
  allowedRootName: string;
  refreshTokenFilePath: string;
  enrollmentFilePath: string;
  publicPort: number;
  adminPort: number;
  gatewayPort: number;
  privateGatewayPort: number;
}

function requiredString(env: Record<string, string | undefined>, key: string): string {
  const value = env[key];
  if (typeof value !== "string" || value.trim().length === 0) {
    throw notConfigured(`Missing required environment variable ${key}`);
  }
  return value.trim();
}

function optionalString(env: Record<string, string | undefined>, key: string): string | undefined {
  const value = env[key];
  if (typeof value !== "string" || value.trim().length === 0) return undefined;
  return value.trim();
}

function readPort(env: Record<string, string | undefined>, key: string, fallback: number): number {
  const raw = optionalString(env, key);
  if (raw === undefined) return fallback;
  if (!/^[0-9]+$/.test(raw)) throw notConfigured(`${key} must be a user-space TCP port`);
  const port = Number.parseInt(raw, 10);
  if (port < MIN_PORT || port > MAX_PORT) throw notConfigured(`${key} must be a user-space TCP port`);
  return port;
}

function readInteger(
  env: Record<string, string | undefined>,
  key: string,
  fallback: number,
  minimum: number,
  maximum: number
): number {
  const raw = optionalString(env, key);
  if (raw === undefined) return fallback;
  if (!/^[0-9]+$/.test(raw)) throw notConfigured(`Invalid ${key}`);
  const value = Number.parseInt(raw, 10);
  if (value < minimum || value > maximum) throw notConfigured(`Invalid ${key}`);
  return value;
}

/**
 * Parses the deployment environment: ports, non-secret OAuth/pairing settings
 * and the three protected secret files. Fails closed with a message naming the
 * offending variable; secret contents never appear in any message.
 */
export async function loadBrokerRuntimeEnvironment(
  env: Record<string, string | undefined>
): Promise<BrokerRuntimeEnvironment> {
  const publicPort = readPort(env, "PORT", DEFAULT_PUBLIC_PORT);
  const adminPort = readPort(env, "GDRIVE_STREAM_ADMIN_PORT", DEFAULT_ADMIN_PORT);
  if (adminPort === publicPort) {
    throw notConfigured(
      "GDRIVE_STREAM_ADMIN_PORT must differ from PORT so the admin surface never shares the public listener"
    );
  }
  const gatewayPort = readPort(env, "GDRIVE_STREAM_GATEWAY_PORT", DEFAULT_GATEWAY_PORT);
  if (gatewayPort === publicPort || gatewayPort === adminPort) {
    throw notConfigured(
      "GDRIVE_STREAM_GATEWAY_PORT must differ from PORT and GDRIVE_STREAM_ADMIN_PORT so the public gateway never shares a listener"
    );
  }

  const privateGatewayPort = readPort(env, "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT", DEFAULT_PRIVATE_GATEWAY_PORT);
  if (privateGatewayPort === publicPort || privateGatewayPort === adminPort || privateGatewayPort === gatewayPort) {
    throw notConfigured(
      "GDRIVE_STREAM_PRIVATE_GATEWAY_PORT must differ from PORT, GDRIVE_STREAM_ADMIN_PORT and GDRIVE_STREAM_GATEWAY_PORT so the private network API gateway never shares a listener"
    );
  }

  const googleClientId = requiredString(env, "GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID");
  const googleCallbackUri = requiredString(env, "GDRIVE_STREAM_GOOGLE_OAUTH_REDIRECT_URI");
  const googleDriveScope = optionalString(env, "GDRIVE_STREAM_GOOGLE_OAUTH_SCOPE") ?? GOOGLE_DRIVE_READONLY_SCOPE;
  // Required, not defaulted: a silent fallback would seal a folder name the
  // operator never chose, while the plugin starts with no root configured.
  const allowedRootName = requiredString(env, "GDRIVE_STREAM_ALLOWED_ROOT_NAME");
  const pairingTtlMs = readInteger(env, "GDRIVE_STREAM_PAIR_TTL_MS", 300_000, 1_000, 10 * 60_000);
  const pairingCapacity = readInteger(env, "GDRIVE_STREAM_PAIRING_CAPACITY", 500, 1, 10_000);
  const pairingRateLimitMaxAttempts = readInteger(env, "GDRIVE_STREAM_PAIR_RATE_LIMIT_MAX_ATTEMPTS", 10, 1, 100);
  const pairingRateLimitWindowMs = readInteger(env, "GDRIVE_STREAM_PAIR_RATE_LIMIT_WINDOW_MS", 60_000, 1_000, 60 * 60_000);

  let config: BrokerRuntimeConfig;
  try {
    config = parseBrokerRuntimeConfig({
      googleClientId,
      googleCallbackUri,
      googleDriveScope,
      pairingTtlMs,
      pairingCapacity,
      pairingRateLimitMaxAttempts,
      pairingRateLimitWindowMs
    });
  } catch (error) {
    throw new RuntimeSecretError(
      "not_configured",
      `Invalid broker runtime configuration: ${error instanceof Error ? error.message : "unknown error"}`,
      { cause: error }
    );
  }

  const clientSecret = await readProtectedSecretFile(requiredString(env, "GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE"));
  const adminToken = await readProtectedSecretFile(requiredString(env, "GDRIVE_STREAM_ADMIN_TOKEN_FILE"));
  if (adminToken.length < MIN_ADMIN_TOKEN_LENGTH) {
    throw notConfigured(
      `GDRIVE_STREAM_ADMIN_TOKEN_FILE must contain at least ${MIN_ADMIN_TOKEN_LENGTH} characters`
    );
  }
  const tokenKey = await readProtectedKeyFile(requiredString(env, "GDRIVE_STREAM_TOKEN_KEY_FILE"));

  return {
    config,
    clientSecret,
    adminToken,
    tokenKey,
    allowedRootName,
    refreshTokenFilePath: requiredString(env, "GDRIVE_STREAM_REFRESH_TOKEN_PATH"),
    enrollmentFilePath: requiredString(env, "GDRIVE_STREAM_ENROLLMENT_PATH"),
    publicPort,
    adminPort,
    gatewayPort,
    privateGatewayPort
  };
}
