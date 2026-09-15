import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { GOOGLE_DRIVE_READONLY_SCOPE, parseBrokerRuntimeConfig } from "../broker/src/config";
import { EnrollmentStore, deviceSigningKeyFingerprint } from "../broker/src/enrollment-store";
import type { OAuthTokenTransport, OAuthTransportRequest } from "../broker/src/google-oauth-client";
import { PairingStore } from "../broker/src/pairing-store";
import { EncryptedRefreshTokenStore } from "../broker/src/refresh-token-store";
// The broker requires an explicit allowed root; tests name a harmless one.
import { createTestBrokerServer as createBrokerServer } from "./support/broker-server";

const CLIENT_SECRET = "test-client-secret-must-not-leak";
const REFRESH_TOKEN = "1//0g-refresh-token-plaintext-must-not-leak";
const ACCESS_TOKEN = "ya29.test-access-token-must-not-leak";
const CODE = "test-authorization-code-must-not-leak";
const CALLBACK_URI = "https://broker.example.test/oauth/google/callback";
const PRIMARY_PATH = "/oauth/google/callback";
const ALTERNATE_PATH = "/gdrive-stream-oauth/google/callback";
// The pairing store is seeded deterministically, so the server-held PKCE verifier is known.
const VERIFIER = Buffer.alloc(32, 7).toString("base64url");

type Server = ReturnType<typeof createBrokerServer>;

const servers: Server[] = [];
const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function devicePublicKeyPem(): string {
  return generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function deviceEncryptionPublicKeyPem(): string {
  return generateKeyPairSync("x25519").publicKey.export({ type: "spki", format: "pem" }).toString();
}

function brokerConfig() {
  return parseBrokerRuntimeConfig({
    googleClientId: "test-client.apps.googleusercontent.com",
    googleCallbackUri: CALLBACK_URI,
    googleDriveScope: GOOGLE_DRIVE_READONLY_SCOPE,
    pairingTtlMs: 300_000,
    pairingCapacity: 50,
    pairingRateLimitMaxAttempts: 100,
    pairingRateLimitWindowMs: 60_000
  });
}

function tokenBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    access_token: ACCESS_TOKEN,
    token_type: "Bearer",
    refresh_token: REFRESH_TOKEN,
    expires_in: 3600,
    scope: GOOGLE_DRIVE_READONLY_SCOPE,
    ...overrides
  });
}

interface Harness {
  baseUrl: string;
  store: EncryptedRefreshTokenStore;
  filePath: string;
  pairingStore: PairingStore;
  requests: OAuthTransportRequest[];
  enrollmentStore: EnrollmentStore;
}

async function startHarness(
  options: { status?: number; body?: string; transport?: OAuthTokenTransport } = {}
): Promise<Harness> {
  const directory = mkdtempSync(join(tmpdir(), "mbrt-callback-"));
  directories.push(directory);
  const filePath = join(directory, "protected", "refresh-token.bin");
  const store = new EncryptedRefreshTokenStore(filePath, Buffer.alloc(32, 7));
  const pairingStore = new PairingStore(() => Buffer.alloc(32, 7));
  const requests: OAuthTransportRequest[] = [];
  const transport: OAuthTokenTransport =
    options.transport ??
    (async (request) => {
      requests.push(request);
      return { status: options.status ?? 200, body: options.body ?? tokenBody() };
    });
  const enrollmentStore = new EnrollmentStore();
  const server = createBrokerServer({
    now: () => 1_000,
    pairingStore,
    enrollmentStore,
    oauth: { config: brokerConfig(), clientSecret: CLIENT_SECRET },
    refreshTokenStore: store,
    oauthTransport: transport
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("test server address missing");
  return { baseUrl: `http://127.0.0.1:${address.port}`, store, filePath, pairingStore, requests, enrollmentStore };
}

async function pair(harness: Harness): Promise<{ pairId: string; oauthState: string }> {
  const devicePublicKey = devicePublicKeyPem();
  const { code } = harness.enrollmentStore.issue({
    nowMs: 1_000,
    ttlMs: 300_000,
    expectedDeviceFingerprint: deviceSigningKeyFingerprint(devicePublicKey)
  });
  const response = await fetch(`${harness.baseUrl}/oauth/pair`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      devicePublicKeyPem: devicePublicKey,
      deviceEncryptionPublicKeyPem: deviceEncryptionPublicKeyPem(),
      enrollmentCode: code
    })
  });
  expect(response.status).toBe(201);
  return (await response.json()) as { pairId: string; oauthState: string };
}

function callbackUrl(baseUrl: string, path: string, params: Record<string, string>): string {
  return `${baseUrl}${path}?${new URLSearchParams(params).toString()}`;
}

describe("self-hosted OAuth callback", () => {
  it("stores the encrypted refresh token and authorizes the pairing after a valid callback", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).not.toContain(CODE);
    expect(await harness.store.read()).toMatchObject({
      refreshToken: REFRESH_TOKEN,
      scope: GOOGLE_DRIVE_READONLY_SCOPE,
      obtainedAtMs: 1_000
    });
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });

    const bytes = readFileSync(harness.filePath);
    expect(bytes.toString("utf8").includes(REFRESH_TOKEN)).toBe(false);
    expect(bytes.includes(Buffer.from(REFRESH_TOKEN, "utf8"))).toBe(false);
  });

  it("handles the alternate callback path identically and rejects every other path", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);

    const alternate = await fetch(callbackUrl(harness.baseUrl, ALTERNATE_PATH, { state: pairing.oauthState, code: CODE }));
    expect(alternate.status).toBe(200);
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });

    const other = await fetch(`${harness.baseUrl}/oauth/google/callback/extra?state=x&code=y`);
    expect(other.status).toBe(404);
  });

  it("rejects a replayed callback state without touching the authorized pairing", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);
    const url = callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE });

    expect((await fetch(url)).status).toBe(200);
    const replay = await fetch(url);

    expect(replay.status).toBe(400);
    expect(await replay.text()).not.toContain(CODE);
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });
  });

  it("does not consume the pairing state when the provider reports an error", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);

    const response = await fetch(
      callbackUrl(harness.baseUrl, PRIMARY_PATH, { error: "access_denied", state: pairing.oauthState, code: CODE })
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.text();
    expect(body).not.toContain("access_denied");
    expect(body).not.toContain(CODE);
    expect(body).not.toContain(pairing.oauthState);
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "pending" });
    // The state is still usable: an error redirect must not burn it.
    expect(harness.pairingStore.consumeOAuthState({ oauthState: pairing.oauthState, nowMs: 2_000 })).toBeDefined();
  });

  it("fails closed without a state or code and never consumes an unknown state", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);

    expect((await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState }))).status).toBe(400);
    expect((await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { code: CODE }))).status).toBe(400);
    expect((await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: "unknown-state", code: CODE }))).status).toBe(400);
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "pending" });
  });

  it("leaves the pairing unauthorized and stores nothing when the token exchange fails", async () => {
    const harness = await startHarness({
      status: 400,
      body: JSON.stringify({ error: "invalid_grant", error_description: "sensitive-provider-detail" })
    });
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(response.status).toBe(400);
    expect(await harness.store.read()).toBeUndefined();
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "callback_state_consumed" });
  });

  it("fails closed and stores nothing when the granted scope is broader than allowed", async () => {
    const harness = await startHarness({
      body: tokenBody({ scope: `${GOOGLE_DRIVE_READONLY_SCOPE} https://www.googleapis.com/auth/drive` })
    });
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(response.status).toBe(400);
    expect(await harness.store.read()).toBeUndefined();
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "callback_state_consumed" });
  });

  it("fails closed and stores nothing when the granted scope omits drive.readonly", async () => {
    const harness = await startHarness({
      body: tokenBody({ scope: "https://www.googleapis.com/auth/drive.metadata.readonly" })
    });
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(response.status).toBe(400);
    expect(await harness.store.read()).toBeUndefined();
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "callback_state_consumed" });
  });

  it("keeps the previously stored record when the token response omits a refresh token", async () => {
    const harness = await startHarness({ body: tokenBody({ refresh_token: undefined }) });
    await harness.store.replace({ refreshToken: "existing-token", scope: GOOGLE_DRIVE_READONLY_SCOPE, obtainedAtMs: 5 });
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(response.status).toBe(200);
    expect(await harness.store.read()).toEqual({
      refreshToken: "existing-token",
      scope: GOOGLE_DRIVE_READONLY_SCOPE,
      obtainedAtMs: 5
    });
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({ hasPlainPairId: false, status: "authorized" });
  });

  it("refuses to authorize a first enrollment when Google omits a refresh token", async () => {
    const harness = await startHarness({ body: tokenBody({ refresh_token: undefined }) });
    const pairing = await pair(harness);

    const response = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    // Without a refresh token the broker would have no durable authorization,
    // so the pairing stops at callback_state_consumed and is never authorized.
    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toContain("Authorization failed");
    expect(await harness.store.read()).toBeUndefined();
    expect(harness.pairingStore.debugRecord(pairing.pairId)).toEqual({
      hasPlainPairId: false,
      status: "callback_state_consumed"
    });
  });

  it("posts the authorization-code exchange with the retained verifier and exact redirect URI", async () => {
    const harness = await startHarness();
    const pairing = await pair(harness);

    await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));

    expect(harness.requests).toHaveLength(1);
    const [request] = harness.requests;
    expect(request.url).toBe("https://oauth2.googleapis.com/token");
    expect(request.method).toBe("POST");
    expect(request.headers["content-type"]).toBe("application/x-www-form-urlencoded");
    expect(Object.fromEntries(new URLSearchParams(request.body))).toEqual({
      grant_type: "authorization_code",
      code: CODE,
      code_verifier: VERIFIER,
      client_id: "test-client.apps.googleusercontent.com",
      client_secret: CLIENT_SECRET,
      redirect_uri: CALLBACK_URI
    });
  });

  it("never reflects the code, state, tokens or client secret in the response or console output", async () => {
    const captured: string[] = [];
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
        captured.push(args.map((value) => (typeof value === "string" ? value : JSON.stringify(value))).join(" "));
      });
    }

    const harness = await startHarness();
    const pairing = await pair(harness);
    const success = await fetch(callbackUrl(harness.baseUrl, PRIMARY_PATH, { state: pairing.oauthState, code: CODE }));
    expect(success.status).toBe(200);
    const successBody = await success.text();

    const failing = await startHarness({ status: 500, body: "upstream-provider-error-text" });
    const failingPairing = await pair(failing);
    const failure = await fetch(callbackUrl(failing.baseUrl, PRIMARY_PATH, { state: failingPairing.oauthState, code: CODE }));
    expect(failure.status).toBe(400);
    const failureBody = await failure.text();

    const output = captured.join("\n");
    for (const secret of [CODE, REFRESH_TOKEN, ACCESS_TOKEN, CLIENT_SECRET, pairing.oauthState, failingPairing.oauthState]) {
      expect(successBody).not.toContain(secret);
      expect(failureBody).not.toContain(secret);
      expect(output).not.toContain(secret);
    }
    expect(failureBody).not.toContain("upstream-provider-error-text");
  });

  it("keeps the callback route disabled when OAuth configuration is absent", async () => {
    const server = createBrokerServer({ now: () => 1_000 });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", () => resolve()));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server address missing");

    const response = await fetch(
      callbackUrl(`http://127.0.0.1:${address.port}`, PRIMARY_PATH, { state: "state", code: "code" })
    );
    expect(response.status).toBe(404);
  });
});
