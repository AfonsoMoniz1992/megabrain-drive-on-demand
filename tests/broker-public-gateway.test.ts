import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { composeBrokerDeployment } from "../broker/src/index";
import {
  createPublicGateway,
  startPublicGateway,
  type PublicGatewayOptions
} from "../broker/src/public-gateway";
import { loadBrokerRuntimeEnvironment } from "../broker/src/runtime-secrets";

/**
 * Public gateway boundary tests.
 *
 * The gateway is the ONLY surface a a private network public reverse proxy path mount may reach; the
 * broker's pairing/claim/nonce/lease/health routes must stay unreachable from
 * it. Every test therefore starts the real gateway on an ephemeral loopback
 * port against a stub upstream, and asserts both the client-visible answer and
 * the exact set of requests the upstream actually saw.
 */

interface RecordedRequest {
  method: string;
  url: string;
}

interface StubUpstream {
  server: Server;
  port: number;
  requests: RecordedRequest[];
}

const closers: Array<() => Promise<void>> = [];
const directories: string[] = [];

afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
  vi.restoreAllMocks();
});

/** Binds an already-created server to an ephemeral loopback port. */
async function listen(server: Server): Promise<number> {
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve());
  });
  closers.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  if (address && typeof address === "object") return address.port;
  throw new Error("server did not bind");
}

/** Starts the exported gateway helper on an ephemeral loopback port. */
async function startGateway(options: PublicGatewayOptions = {}): Promise<{ server: Server; port: number }> {
  const server = await startPublicGateway({ ...options, port: 0 });
  closers.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address !== "object") throw new Error("gateway did not bind");
  return { server, port: address.port };
}

async function startStub(
  handler?: (request: IncomingMessage, response: ServerResponse) => void
): Promise<StubUpstream> {
  const requests: RecordedRequest[] = [];
  const server = createServer((request, response) => {
    requests.push({ method: request.method ?? "", url: request.url ?? "" });
    if (handler) {
      handler(request, response);
      return;
    }
    response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    response.end("<!doctype html><html><body>authorization complete</body></html>");
  });
  const port = await listen(server);
  return { server, port, requests };
}

/** A loopback port nothing is listening on, so upstream calls are refused. */
async function closedLoopbackPort(): Promise<number> {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

const PROTECTED_PATHS = ["/health", "/oauth/pair", "/oauth/claim", "/oauth/nonce", "/oauth/lease"];

describe("public gateway forwarding", () => {
  it("forwards the whitelisted path with the broker path rewritten and the query preserved", async () => {
    const stub = await startStub();
    const { server, port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const address = server.address();
    expect(address && typeof address === "object" ? address.address : undefined).toBe("127.0.0.1");

    const response = await fetch(`http://127.0.0.1:${port}/google/callback?state=state-value-1&code=code-value-1`);

    expect(response.status).toBe(200);
    expect(await response.text()).toContain("authorization complete");
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(stub.requests).toEqual([
      { method: "GET", url: "/oauth/google/callback?state=state-value-1&code=code-value-1" }
    ]);
  });

  it("preserves a provider error redirect's query and passes the upstream status through", async () => {
    const stub = await startStub((_request, response) => {
      response.writeHead(400, { "content-type": "text/html; charset=utf-8" });
      response.end("<html><body>authorization failed</body></html>");
    });
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const response = await fetch(`http://127.0.0.1:${port}/google/callback?error=access_denied&state=state-2`);

    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toContain("authorization failed");
    expect(stub.requests).toEqual([{ method: "GET", url: "/oauth/google/callback?error=access_denied&state=state-2" }]);
  });

  it("forwarding carries no request body and no client headers", async () => {
    const seen: Array<{ method: string; url: string; body: string; cookie?: string }> = [];
    const stub = await startStub(async (request, response) => {
      let body = "";
      for await (const chunk of request) body += String(chunk);
      seen.push({ method: request.method ?? "", url: request.url ?? "", body, cookie: request.headers.cookie });
      response.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      response.end("ok");
    });
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    await fetch(`http://127.0.0.1:${port}/google/callback?code=code-value-2`, {
      headers: { cookie: "session=broker-cookie", "x-forwarded-for": "203.0.113.7" }
    });

    expect(seen).toEqual([{ method: "GET", url: "/oauth/google/callback?code=code-value-2", body: "", cookie: undefined }]);
  });

  it.each(PROTECTED_PATHS)(
    "answers 404 for GET and POST %s and never calls the upstream",
    async (path) => {
      const stub = await startStub();
      const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

      for (const method of ["GET", "POST"] as const) {
        const response = await fetch(`http://127.0.0.1:${port}${path}`, { method });
        expect(response.status).toBe(404);
        expect(response.headers.get("cache-control")).toBe("no-store");
        expect(response.headers.get("x-content-type-options")).toBe("nosniff");
        expect(await response.json()).toEqual({ error: "not_found" });
      }

      expect(stub.requests).toHaveLength(0);
    }
  );

  it("does not treat a longer path that merely starts with the whitelist as the callback", async () => {
    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const response = await fetch(`http://127.0.0.1:${port}/google/callback/extra?code=code-value-3`);

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
    expect(stub.requests).toHaveLength(0);
  });

  it("refuses non-GET requests on the whitelisted path with 405 and no upstream call", async () => {
    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    for (const method of ["POST", "PUT", "DELETE"] as const) {
      const response = await fetch(`http://127.0.0.1:${port}/google/callback?code=code-value-4`, { method });
      expect(response.status).toBe(405);
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(await response.json()).toEqual({ error: "method_not_allowed" });
    }

    expect(stub.requests).toHaveLength(0);
  });

  it("maps an unreachable upstream to a bare 502 without leaking internals", async () => {
    const deadPort = await closedLoopbackPort();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${deadPort}` });

    const response = await fetch(`http://127.0.0.1:${port}/google/callback?code=code-value-5`);

    expect(response.status).toBe(502);
    expect(response.headers.get("cache-control")).toBe("no-store");
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: "upstream_unavailable" });
    expect(body).not.toContain("ECONNREFUSED");
    expect(body).not.toContain(String(deadPort));
  });

  it("bounds the upstream request with the configured timeout", async () => {
    // A stub that accepts the connection and never answers.
    const stub = await startStub(() => undefined);
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}`, timeoutMs: 150 });

    const startedAt = Date.now();
    const response = await fetch(`http://127.0.0.1:${port}/google/callback?code=code-value-6`);

    expect(response.status).toBe(502);
    expect(JSON.parse(await response.text())).toEqual({ error: "upstream_unavailable" });
    expect(Date.now() - startedAt).toBeLessThan(5_000);
  });
});

describe("public gateway configuration", () => {
  it.each([
    "http://example.test:34003",
    "http://203.0.113.7:34003",
    "http://0.0.0.0:34003",
    "https://127.0.0.1:34003",
    "https://broker.example.test",
    "ftp://127.0.0.1:34003",
    "not-a-url",
    ""
  ])("rejects a non-loopback http upstream: %s", (upstream) => {
    expect(() => createPublicGateway({ upstream })).toThrow(/loopback/i);
  });

  it("accepts the documented loopback upstream forms and binds nothing until asked", () => {
    for (const upstream of ["http://127.0.0.1:34003", "http://127.0.0.1", "http://localhost:34003", "http://[::1]:34003"]) {
      const server = createPublicGateway({ upstream });
      expect(server.listening).toBe(false);
      expect(server).toBeInstanceOf(Object);
    }
    expect(createPublicGateway().listening).toBe(false);
  });

  it("rejects a whitelist path that is not an absolute exact path", () => {
    expect(() => createPublicGateway({ publicPath: "google/callback" })).toThrow(/path/i);
    expect(() => createPublicGateway({ upstreamPath: "" })).toThrow(/path/i);
  });
});

describe("public gateway logging", () => {
  it("never writes query, state, code or error values to any console channel", async () => {
    const output: string[] = [];
    for (const channel of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, channel).mockImplementation((...args: unknown[]) => {
        output.push(args.map(String).join(" "));
      });
    }

    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    await fetch(`http://127.0.0.1:${port}/google/callback?state=state-secret-9&code=code-secret-9`);
    await fetch(`http://127.0.0.1:${port}/oauth/claim`, { method: "POST" });

    const joined = output.join("\n");
    expect(joined).not.toContain("state-secret-9");
    expect(joined).not.toContain("code-secret-9");
    expect(joined).not.toContain("state");
    expect(joined).not.toContain("code");
  });
});

const CLIENT_SECRET = "gateway-client-secret-must-not-be-logged";
const ADMIN_TOKEN = "gateway-admin-token-must-not-be-logged";
const KEY_BASE64 = Buffer.alloc(32, 23).toString("base64");

function protectedFile(directory: string, name: string, contents: string): string {
  const filePath = join(directory, name);
  writeFileSync(filePath, contents, { mode: 0o600 });
  chmodSync(filePath, 0o600);
  return filePath;
}

function validEnvironment(): Record<string, string> {
  const directory = mkdtempSync(join(tmpdir(), "mbrs-gateway-"));
  directories.push(directory);
  return {
    PORT: "34003",
    GDRIVE_STREAM_ADMIN_PORT: "34004",
    GDRIVE_STREAM_GOOGLE_OAUTH_CLIENT_ID: "test-client.apps.googleusercontent.com",
    GDRIVE_STREAM_GOOGLE_OAUTH_REDIRECT_URI: "https://broker.example.test/gdrive-stream-oauth/google/callback",
    GDRIVE_STREAM_ALLOWED_ROOT_NAME: "example-test-root",
    GDRIVE_STREAM_OAUTH_CLIENT_SECRET_FILE: protectedFile(directory, "client-secret", `${CLIENT_SECRET}\n`),
    GDRIVE_STREAM_ADMIN_TOKEN_FILE: protectedFile(directory, "admin-token", ADMIN_TOKEN),
    GDRIVE_STREAM_TOKEN_KEY_FILE: protectedFile(directory, "token-key", KEY_BASE64),
    GDRIVE_STREAM_REFRESH_TOKEN_PATH: join(directory, "protected", "refresh-token.bin"),
    GDRIVE_STREAM_ENROLLMENT_PATH: join(directory, "protected", "enrollment.bin")
  };
}

describe("gateway deployment wiring", () => {
  it("defaults the gateway to its own loopback port and refuses any port collision", async () => {
    const env = validEnvironment();
    expect((await loadBrokerRuntimeEnvironment(env)).gatewayPort).toBe(34005);
    expect((await loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_GATEWAY_PORT: "40009" })).gatewayPort).toBe(40009);

    await expect(loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_GATEWAY_PORT: "34003" })).rejects.toThrow(
      /GDRIVE_STREAM_GATEWAY_PORT/
    );
    await expect(loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_GATEWAY_PORT: "34004" })).rejects.toThrow(
      /GDRIVE_STREAM_GATEWAY_PORT/
    );
    await expect(loadBrokerRuntimeEnvironment({ ...env, GDRIVE_STREAM_GATEWAY_PORT: "70000" })).rejects.toThrow(
      /GDRIVE_STREAM_GATEWAY_PORT/
    );
  });

  it("composes a third, non-listening gateway surface and keeps its secrets out of the facts", async () => {
    const deployment = await composeBrokerDeployment(validEnvironment());

    expect(deployment.facts.gatewayPort).toBe(34005);
    expect(deployment.gatewayServer.listening).toBe(false);
    expect(deployment.gatewayServer).not.toBe(deployment.publicServer);
    expect(deployment.gatewayServer).not.toBe(deployment.adminServer);

    const serialised = JSON.stringify(deployment.facts);
    expect(serialised).not.toContain(CLIENT_SECRET);
    expect(serialised).not.toContain(ADMIN_TOKEN);
    expect(serialised).not.toContain(KEY_BASE64);
  });
});
