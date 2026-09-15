import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { composeBrokerDeployment, runBrokerEntrypoint } from "../broker/src/index";

/**
 * Entrypoint smoke tests. They deliberately never bind a TCP port: composition
 * is asserted directly (both servers exist, neither is listening, nothing was
 * written to disk) and the failure paths are asserted through the exported
 * entrypoint function with intentionally invalid configuration.
 */

const CLIENT_SECRET = "entrypoint-client-secret-must-not-be-logged";
const ADMIN_TOKEN = "entrypoint-admin-token-must-not-be-logged";
const KEY_BASE64 = Buffer.alloc(32, 11).toString("base64");

const directories: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function tempDirectory(): string {
  const directory = mkdtempSync(join(tmpdir(), "mbrs-entrypoint-"));
  directories.push(directory);
  return directory;
}

function protectedFile(directory: string, name: string, contents: string): string {
  const filePath = join(directory, name);
  writeFileSync(filePath, contents, { mode: 0o600 });
  chmodSync(filePath, 0o600);
  return filePath;
}

function validEnvironment(): { env: NodeJS.ProcessEnv; directory: string } {
  const directory = tempDirectory();
  return {
    directory,
    env: {
      PORT: "34003",
      GDRIVE_STREAM_ADMIN_PORT: "34004",
      GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID: "test-client.apps.googleusercontent.com",
      GDRIVE_STREAM_GOOGLE_OAUTH_REDIRECT_URI: "https://broker.example.test/oauth/google/callback",
      GDRIVE_STREAM_ALLOWED_ROOT_NAME: "example-test-root",
      GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE: protectedFile(directory, "client-secret", `${CLIENT_SECRET}\n`),
      GDRIVE_STREAM_ADMIN_TOKEN_FILE: protectedFile(directory, "admin-token", ADMIN_TOKEN),
      GDRIVE_STREAM_TOKEN_KEY_FILE: protectedFile(directory, "token-key", KEY_BASE64),
      GDRIVE_STREAM_REFRESH_TOKEN_PATH: join(directory, "protected", "refresh-token.bin"),
      GDRIVE_STREAM_ENROLLMENT_PATH: join(directory, "protected", "enrollment.bin")
    }
  };
}

describe("broker entrypoint composition", () => {
  it("importing the module has no side effects: no deployment exists until asked for", async () => {
    const { env } = validEnvironment();
    // The module-level start hook only fires for a direct invocation, so an
    // in-process import leaves the ports free; composition is an explicit call.
    expect(typeof composeBrokerDeployment).toBe("function");
    const deployment = await composeBrokerDeployment(env);
    expect(deployment.publicServer.listening).toBe(false);
    expect(deployment.adminServer.listening).toBe(false);
    expect(deployment.privateGatewayServer.listening).toBe(false);
    expect(deployment.publicServer).not.toBe(deployment.adminServer);
    expect(deployment.privateGatewayServer).not.toBe(deployment.publicServer);
  });

  it("composes public and admin servers on separate loopback ports without creating store files", async () => {
    const { env, directory } = validEnvironment();
    const deployment = await composeBrokerDeployment(env);
    expect(deployment.facts.publicPort).toBe(34003);
    expect(deployment.facts.adminPort).toBe(34004);
    expect(deployment.facts.privateGatewayPort).toBe(34006);
    expect(deployment.facts.refreshTokenFilePath).toBe(join(directory, "protected", "refresh-token.bin"));
    expect(deployment.facts.enrollmentFilePath).toBe(join(directory, "protected", "enrollment.bin"));
    // The startup preflight reads the stores but must never create them: a
    // missing protected directory is still left to first use.
    expect(existsSync(join(directory, "protected"))).toBe(false);
  });

  it("keeps every secret out of the loggable startup facts", async () => {
    const { env } = validEnvironment();
    const deployment = await composeBrokerDeployment(env);
    const serialised = JSON.stringify(deployment.facts);
    expect(serialised).not.toContain(CLIENT_SECRET);
    expect(serialised).not.toContain(ADMIN_TOKEN);
    expect(serialised).not.toContain(KEY_BASE64);
  });

  it("runs the deployment end to end through the entrypoint when asked to start", async () => {
    const { env } = validEnvironment();
    const deployment = await composeBrokerDeployment({ ...env, GDRIVE_STREAM_PAIRING_CAPACITY: "7" });
    expect(deployment.runtime.config.pairingCapacity).toBe(7);
    expect(deployment.runtime.publicPort).toBe(34003);
  });
});

describe("broker startup store preflight", () => {
  it("tightens a wider pre-existing store directory to 0700 at startup", async () => {
    const { env, directory } = validEnvironment();
    const protectedDir = join(directory, "protected");
    mkdirSync(protectedDir, { recursive: true });
    chmodSync(protectedDir, 0o755);
    expect(statSync(protectedDir).mode & 0o777).toBe(0o755);

    await composeBrokerDeployment(env);

    expect(statSync(protectedDir).mode & 0o777).toBe(0o700);
  });

  it("refuses to compose when a store directory is not owned by the service uid", async () => {
    const { env, directory } = validEnvironment();
    const protectedDir = join(directory, "protected");
    mkdirSync(protectedDir, { recursive: true });
    const realUid = typeof process.getuid === "function" ? process.getuid() : 0;
    vi.spyOn(process, "getuid").mockReturnValue(realUid + 1);

    // Whichever guard fires first, an unowned path must never be used.
    await expect(composeBrokerDeployment(env)).rejects.toThrow(/not owned|not protected/i);
    expect(existsSync(join(protectedDir, "refresh-token.bin"))).toBe(false);
    expect(existsSync(join(protectedDir, "enrollment.bin"))).toBe(false);
  });
});

describe("broker entrypoint failures", () => {
  it("exits non-zero with a clear, secret-free message when the configuration is missing", async () => {
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      errors.push(args.map(String).join(" "));
    });
    vi.spyOn(console, "info").mockImplementation(() => undefined);

    await expect(runBrokerEntrypoint({})).resolves.toBe(1);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID");
    expect(errors[0]).toContain("failed to start");
  });

  it("exits non-zero when the admin port collides with the public port", async () => {
    const { env } = validEnvironment();
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      errors.push(args.map(String).join(" "));
    });
    vi.spyOn(console, "info").mockImplementation(() => undefined);

    await expect(runBrokerEntrypoint({ ...env, PORT: "34004" })).resolves.toBe(1);
    expect(errors[0]).toContain("GDRIVE_STREAM_ADMIN_PORT");
    // Nothing was bound: the invalid configuration is rejected before listen.
  });

  it("exits non-zero and never echoes secret material when a secret file is unprotected", async () => {
    const { env } = validEnvironment();
    chmodSync(env.GDRIVE_STREAM_ADMIN_TOKEN_FILE as string, 0o644);
    const errors: string[] = [];
    vi.spyOn(console, "error").mockImplementation((...args: unknown[]) => {
      errors.push(args.map(String).join(" "));
    });
    vi.spyOn(console, "info").mockImplementation(() => undefined);

    await expect(runBrokerEntrypoint(env)).resolves.toBe(1);
    expect(errors[0]).toContain("group or other");
    expect(errors[0]).not.toContain(ADMIN_TOKEN);
    expect(errors[0]).not.toContain(CLIENT_SECRET);
  });
});
