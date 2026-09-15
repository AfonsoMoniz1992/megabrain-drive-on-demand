import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  RuntimeSecretError,
  loadBrokerRuntimeEnvironment,
  readProtectedKeyFile,
  readProtectedSecretFile
} from "../broker/src/runtime-secrets";

const CLIENT_SECRET = "client-secret-value-must-never-be-logged";
const ADMIN_TOKEN = "operator-admin-token-value-must-never-be-logged";
const KEY_BASE64 = Buffer.alloc(32, 5).toString("base64");

const directories: string[] = [];

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "mbrs-"));
  directories.push(directory);
  return directory;
}

afterEach(() => {
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

/** Writes a secret file with explicit mode (0600 unless the test widens it). */
function writeProtectedFile(directory: string, name: string, contents: string, mode = 0o600): string {
  const filePath = join(directory, name);
  writeFileSync(filePath, contents, { mode });
  chmodSync(filePath, mode);
  return filePath;
}

async function captureFailure(action: () => Promise<unknown>): Promise<RuntimeSecretError> {
  try {
    await action();
  } catch (error) {
    return error as RuntimeSecretError;
  }
  throw new Error("expected the helper to fail closed, but it resolved");
}

async function expectFailClosed(action: () => Promise<unknown>, code: string): Promise<RuntimeSecretError> {
  const error = await captureFailure(action);
  expect(error).toBeInstanceOf(RuntimeSecretError);
  expect(error.code).toBe(code);
  return error;
}

/** A complete, valid environment whose secret files live in a fresh temp dir. */
function validEnvironment(): { env: NodeJS.ProcessEnv; directory: string } {
  const directory = tempDirectory();
  mkdirSync(join(directory, "protected"), { mode: 0o700 });
  const env: NodeJS.ProcessEnv = {
    PORT: "34003",
    GDRIVE_STREAM_ADMIN_PORT: "34004",
    GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID: "test-client.apps.googleusercontent.com",
    GDRIVE_STREAM_GOOGLE_OAUTH_REDIRECT_URI: "https://broker.example.test/oauth/google/callback",
    GDRIVE_STREAM_ALLOWED_ROOT_NAME: "example-test-root",
    GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE: writeProtectedFile(directory, "client-secret", `${CLIENT_SECRET}\n`),
    GDRIVE_STREAM_ADMIN_TOKEN_FILE: writeProtectedFile(directory, "admin-token", ADMIN_TOKEN),
    GDRIVE_STREAM_TOKEN_KEY_FILE: writeProtectedFile(directory, "token-key", KEY_BASE64),
    GDRIVE_STREAM_REFRESH_TOKEN_PATH: join(directory, "protected", "refresh-token.bin"),
    GDRIVE_STREAM_ENROLLMENT_PATH: join(directory, "protected", "enrollment.bin")
  };
  return { env, directory };
}

describe("readProtectedSecretFile", () => {
  it("reads a protected secret file and trims surrounding whitespace", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "secret", `\n${CLIENT_SECRET}\n`);
    await expect(readProtectedSecretFile(filePath)).resolves.toBe(CLIENT_SECRET);
  });

  it("fails closed when the path is missing, naming the path but not a value", async () => {
    const directory = tempDirectory();
    const filePath = join(directory, "absent");
    const error = await expectFailClosed(() => readProtectedSecretFile(filePath), "missing_file");
    expect(error.message).toContain(filePath);
  });

  it("refuses anything that is not a regular file", async () => {
    const directory = tempDirectory();
    await expectFailClosed(() => readProtectedSecretFile(directory), "not_regular_file");
    const target = writeProtectedFile(directory, "target", CLIENT_SECRET);
    const link = join(directory, "link");
    const { symlinkSync } = await import("node:fs");
    symlinkSync(target, link);
    await expectFailClosed(() => readProtectedSecretFile(link), "not_regular_file");
  });

  it("refuses a file readable by group or other", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "wide", CLIENT_SECRET, 0o644);
    const error = await expectFailClosed(() => readProtectedSecretFile(filePath), "insecure_permissions");
    expect(error.message).not.toContain(CLIENT_SECRET);
  });

  it("refuses even a single group-readable bit", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "group", CLIENT_SECRET, 0o640);
    await expectFailClosed(() => readProtectedSecretFile(filePath), "insecure_permissions");
  });

  it("refuses a file owned by another uid", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "foreign", CLIENT_SECRET);
    const error = await expectFailClosed(() => readProtectedSecretFile(filePath, { uid: 4242 }), "not_owned");
    expect(error.message).not.toContain(CLIENT_SECRET);
  });

  it("accepts a file when the injected uid matches the file owner", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "owned", CLIENT_SECRET);
    const inferred = (await import("node:fs")).statSync(filePath).uid;
    await expect(readProtectedSecretFile(filePath, { uid: inferred })).resolves.toBe(CLIENT_SECRET);
  });

  it("accepts a root-controlled group-readable file for the service group", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "root-controlled", CLIENT_SECRET, 0o640);
    const stats = (await import("node:fs")).statSync(filePath);
    await expect(
      readProtectedSecretFile(filePath, { uid: 4242, gid: stats.gid, rootUid: stats.uid })
    ).resolves.toBe(CLIENT_SECRET);
  });

  it("refuses an empty secret rather than returning a blank credential", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "empty", "   \n");
    await expectFailClosed(() => readProtectedSecretFile(filePath), "empty_secret");
  });
});

describe("readProtectedKeyFile", () => {
  it("decodes a 32-byte base64 key", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "key", `${KEY_BASE64}\n`);
    await expect(readProtectedKeyFile(filePath)).resolves.toEqual(Buffer.alloc(32, 5));
  });

  it("decodes an unpadded base64 key", async () => {
    const directory = tempDirectory();
    const unpadded = Buffer.alloc(32, 5).toString("base64").replace(/=+$/, "");
    const filePath = writeProtectedFile(directory, "key", unpadded);
    await expect(readProtectedKeyFile(filePath)).resolves.toEqual(Buffer.alloc(32, 5));
  });

  it("refuses a key that is not exactly 32 bytes", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "short", Buffer.alloc(16, 1).toString("base64"));
    await expectFailClosed(() => readProtectedKeyFile(filePath), "invalid_key_length");
  });

  it("refuses a value that is not valid base64", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "bogus", "not!a!base64!value");
    const error = await expectFailClosed(() => readProtectedKeyFile(filePath), "invalid_base64");
    expect(error.message).not.toContain("not!a!base64!value");
  });

  it("applies the same file protections as a secret file", async () => {
    const directory = tempDirectory();
    const filePath = writeProtectedFile(directory, "key", KEY_BASE64, 0o644);
    await expectFailClosed(() => readProtectedKeyFile(filePath), "insecure_permissions");
  });
});

describe("loadBrokerRuntimeEnvironment", () => {
  it("loads the full runtime environment with defaults and protected secrets", async () => {
    const { env, directory } = validEnvironment();
    const runtime = await loadBrokerRuntimeEnvironment(env);
    expect(runtime.config).toMatchObject({
      googleClientId: "test-client.apps.googleusercontent.com",
      googleCallbackUri: "https://broker.example.test/oauth/google/callback",
      googleDriveScope: "https://www.googleapis.com/auth/drive.readonly",
      pairingTtlMs: 300_000,
      pairingCapacity: 500,
      pairingRateLimitMaxAttempts: 10,
      pairingRateLimitWindowMs: 60_000
    });
    expect(runtime.clientSecret).toBe(CLIENT_SECRET);
    expect(runtime.adminToken).toBe(ADMIN_TOKEN);
    expect(runtime.tokenKey).toEqual(Buffer.alloc(32, 5));
    expect(runtime.adminPort).toBe(34004);
    expect(runtime.privateGatewayPort).toBe(34006);
    expect(runtime.allowedRootName).toBe("example-test-root");
    expect(runtime.refreshTokenFilePath).toBe(join(directory, "protected", "refresh-token.bin"));
    expect(runtime.enrollmentFilePath).toBe(join(directory, "protected", "enrollment.bin"));
  });

  it("takes the allowed root from configuration only, with no silent fallback", async () => {
    // A non-default operator root must flow through unchanged...
    const { env } = validEnvironment();
    const configured = await loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_ALLOWED_ROOT_NAME: "operator-test-root" });
    expect(configured.allowedRootName).toBe("operator-test-root");

    // ...and an absent variable must fail closed rather than invent a root.
    const missing = validEnvironment();
    delete missing.env.GDRIVE_STREAM_ALLOWED_ROOT_NAME;
    const error = await expectFailClosed(() => loadBrokerRuntimeEnvironment(missing.env), "not_configured");
    expect(error.message).toContain("GDRIVE_STREAM_ALLOWED_ROOT_NAME");
  });

  it("honours explicit pairing limits and ports", async () => {
    const { env } = validEnvironment();
    const runtime = await loadBrokerRuntimeEnvironment({
      ...env,
      PORT: "40001",
      GDRIVE_STREAM_ADMIN_PORT: "40002",
      GDRIVE_STREAM_PAIR_TTL_MS: "120000",
      GDRIVE_STREAM_PAIRING_CAPACITY: "25",
      GDRIVE_STREAM_PAIR_RATE_LIMIT_MAX_ATTEMPTS: "4",
      GDRIVE_STREAM_PAIR_RATE_LIMIT_WINDOW_MS: "30000"
    });
    expect(runtime.adminPort).toBe(40002);
    expect(runtime.config).toMatchObject({
      pairingTtlMs: 120_000,
      pairingCapacity: 25,
      pairingRateLimitMaxAttempts: 4,
      pairingRateLimitWindowMs: 30_000
    });
  });

  it.each([
    "GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID",
    "GDRIVE_STREAM_GOOGLE_OAUTH_REDIRECT_URI",
    "GDRIVE_STREAM_ALLOWED_ROOT_NAME",
    "GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE",
    "GDRIVE_STREAM_ADMIN_TOKEN_FILE",
    "GDRIVE_STREAM_TOKEN_KEY_FILE",
    "GDRIVE_STREAM_REFRESH_TOKEN_PATH",
    "GDRIVE_STREAM_ENROLLMENT_PATH"
  ])("fails closed naming the missing variable %s", async (key) => {
    const { env } = validEnvironment();
    delete env[key];
    const error = await expectFailClosed(() => loadBrokerRuntimeEnvironment(env), "not_configured");
    expect(error.message).toContain(key);
  });

  it("refuses an admin port that collides with the public port", async () => {
    const { env } = validEnvironment();
    const error = await expectFailClosed(
      () => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_ADMIN_PORT: env.PORT as string }),
      "not_configured"
    );
    expect(error.message).toContain("GDRIVE_STREAM_ADMIN_PORT");
  });

  it("refuses a private gateway port that collides with any other listener", async () => {
    const { env } = validEnvironment();
    for (const conflictingPort of [env.PORT, env.GDRIVE_STREAM_ADMIN_PORT, "34005"]) {
      const error = await expectFailClosed(
        () => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_PRIVATE_GATEWAY_PORT: conflictingPort }),
        "not_configured"
      );
      expect(error.message).toContain("GDRIVE_STREAM_PRIVATE_GATEWAY_PORT");
    }
  });

  it("refuses out-of-range or non-integer ports", async () => {
    const { env } = validEnvironment();
    await expectFailClosed(() => loadBrokerRuntimeEnvironment({ ...env, PORT: "80" }), "not_configured");
    await expectFailClosed(() => loadBrokerRuntimeEnvironment({ ...env, PORT: "not-a-port" }), "not_configured");
    await expectFailClosed(() => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_ADMIN_PORT: "70000" }), "not_configured");
  });

  it("refuses non-integer pairing limits", async () => {
    const { env } = validEnvironment();
    for (const key of [
      "GDRIVE_STREAM_PAIR_TTL_MS",
      "GDRIVE_STREAM_PAIRING_CAPACITY",
      "GDRIVE_STREAM_PAIR_RATE_LIMIT_MAX_ATTEMPTS",
      "GDRIVE_STREAM_PAIR_RATE_LIMIT_WINDOW_MS"
    ]) {
      const error = await expectFailClosed(
        () => loadBrokerRuntimeEnvironment({ ...env, [key]: "not-a-number" }),
        "not_configured"
      );
      expect(error.message).toContain(key);
    }
  });

  it("refuses an OAuth scope other than the read-only Drive scope", async () => {
    const { env } = validEnvironment();
    await expectFailClosed(
      () => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_GOOGLE_OAUTH_SCOPE: "https://www.googleapis.com/auth/drive" }),
      "not_configured"
    );
  });

  it("refuses an admin token that is too short to be a real credential", async () => {
    const { env } = validEnvironment();
    const error = await expectFailClosed(
      () => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_ADMIN_TOKEN_FILE: writeProtectedFile(tempDirectory(), "short-token", "short") }),
      "not_configured"
    );
    expect(error.message).toContain("GDRIVE_STREAM_ADMIN_TOKEN_FILE");
  });

  it("refuses a token key file that is not exactly 32 bytes", async () => {
    const { env } = validEnvironment();
    await expectFailClosed(
      () => loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_TOKEN_KEY_FILE: writeProtectedFile(tempDirectory(), "short-key", Buffer.alloc(8, 1).toString("base64")) }),
      "invalid_key_length"
    );
  });

  it("propagates the protected-file guard for a world-readable admin token", async () => {
    const { env } = validEnvironment();
    chmodSync(env.GDRIVE_STREAM_ADMIN_TOKEN_FILE as string, 0o644);
    const error = await expectFailClosed(
      () => loadBrokerRuntimeEnvironment(env),
      "insecure_permissions"
    );
    expect(error.message).not.toContain(ADMIN_TOKEN);
  });

  it("never echoes secret material from a failed load", async () => {
    const { env } = validEnvironment();
    chmodSync(env.GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE as string, 0o604);
    const error = await expectFailClosed(() => loadBrokerRuntimeEnvironment(env), "insecure_permissions");
    expect(error.message).not.toContain(CLIENT_SECRET);
  });
});
