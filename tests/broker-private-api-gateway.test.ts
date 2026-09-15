import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createPrivateApiGateway,
  startPrivateApiGateway,
  type PrivateApiGatewayOptions
} from "../broker/src/private-api-gateway";

interface RecordedRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
}

interface StubUpstream {
  server: Server;
  port: number;
  requests: RecordedRequest[];
}

const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const close of closers.splice(0)) await close();
  vi.restoreAllMocks();
});

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

async function startGateway(options: PrivateApiGatewayOptions = {}): Promise<{ server: Server; port: number }> {
  const server = await startPrivateApiGateway({ ...options, port: 0 });
  closers.push(() => new Promise<void>((resolve) => server.close(() => resolve())));
  const address = server.address();
  if (!address || typeof address !== "object") throw new Error("gateway did not bind");
  return { server, port: address.port };
}

async function startStub(
  handler?: (request: IncomingMessage, response: ServerResponse) => void | Promise<void>
): Promise<StubUpstream> {
  const requests: RecordedRequest[] = [];
  const server = createServer(async (request, response) => {
    let body = "";
    for await (const chunk of request) body += String(chunk);
    requests.push({ method: request.method ?? "", url: request.url ?? "", headers: request.headers, body });
    if (handler) {
      await handler(request, response);
      return;
    }
    response.writeHead(201, { "content-type": "application/json; charset=utf-8" });
    response.end(JSON.stringify({ received: body }));
  });
  const port = await listen(server);
  return { server, port, requests };
}

async function closedLoopbackPort(): Promise<number> {
  const probe = createServer();
  const port = await listen(probe);
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

const ALLOWED_PATHS = ["/oauth/pair", "/oauth/claim", "/oauth/nonce", "/oauth/lease"];

describe("private API gateway forwarding", () => {
  it.each(ALLOWED_PATHS)("forwards an exact POST %s with its JSON body and only JSON content type", async (path) => {
    const stub = await startStub();
    const { server, port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });
    const body = JSON.stringify({ path, proof: "test-proof" });

    const address = server.address();
    expect(address && typeof address === "object" ? address.address : undefined).toBe("127.0.0.1");
    const response = await fetch(`http://127.0.0.1:${port}${path}`, {
      method: "POST",
      headers: {
        "content-type": "application/json; charset=utf-8",
        authorization: "Bearer must-not-forward",
        cookie: "session=must-not-forward",
        "x-forwarded-for": "203.0.113.9",
        "x-client-extra": "must-not-forward"
      },
      body
    });

    expect(response.status).toBe(201);
    expect(await response.json()).toEqual({ received: body });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(stub.requests).toHaveLength(1);
    expect(stub.requests[0]).toMatchObject({ method: "POST", url: path, body });
    expect(stub.requests[0].headers["content-type"]).toBe("application/json");
    expect(stub.requests[0].headers.authorization).toBeUndefined();
    expect(stub.requests[0].headers.cookie).toBeUndefined();
    expect(stub.requests[0].headers["x-forwarded-for"]).toBeUndefined();
    expect(stub.requests[0].headers["x-client-extra"]).toBeUndefined();
  });

  it.each([
    ["GET", "/oauth/pair"],
    ["POST", "/health"],
    ["POST", "/oauth/google/callback"],
    ["POST", "/oauth/unknown"]
  ])("returns bare 404 for %s %s without calling upstream", async (method, path) => {
    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, body: method === "POST" ? "{}" : undefined });

    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(stub.requests).toHaveLength(0);
  });

  it("rejects malformed and oversized JSON request bodies locally", async () => {
    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const malformed = await fetch(`http://127.0.0.1:${port}/oauth/pair`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not-json"
    });
    expect(malformed.status).toBe(400);
    expect(await malformed.json()).toEqual({ error: "invalid_request" });

    const oversized = await fetch(`http://127.0.0.1:${port}/oauth/pair`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "x".repeat(8_193)
    });
    expect(oversized.status).toBe(413);
    expect(await oversized.json()).toEqual({ error: "payload_too_large" });
    expect(stub.requests).toHaveLength(0);
  });

  it("passes upstream status and body through while adding no-store and nosniff", async () => {
    const stub = await startStub((_request, response) => {
      response.writeHead(409, { "content-type": "application/json" });
      response.end('{"error":"not_authorized_yet"}');
    });
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    const response = await fetch(`http://127.0.0.1:${port}/oauth/claim`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}"
    });

    expect(response.status).toBe(409);
    expect(await response.text()).toBe('{"error":"not_authorized_yet"}');
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
  });

  it("maps an unavailable upstream to a sanitized 502", async () => {
    const deadPort = await closedLoopbackPort();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${deadPort}` });

    const response = await fetch(`http://127.0.0.1:${port}/oauth/lease`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}"
    });

    expect(response.status).toBe(502);
    const body = await response.text();
    expect(JSON.parse(body)).toEqual({ error: "upstream_unavailable" });
    expect(body).not.toContain("ECONNREFUSED");
    expect(body).not.toContain(String(deadPort));
  });
});

describe("private API gateway configuration and logging", () => {
  it.each([
    "http://example.test:34003",
    "http://203.0.113.7:34003",
    "http://0.0.0.0:34003",
    "https://127.0.0.1:34003",
    "ftp://127.0.0.1:34003",
    "not-a-url"
  ])("rejects non-loopback HTTP upstream %s", (upstream) => {
    expect(() => createPrivateApiGateway({ upstream })).toThrow(/loopback/i);
  });

  it("creates an unbound default gateway and never writes to console", async () => {
    expect(createPrivateApiGateway().listening).toBe(false);
    const output: string[] = [];
    for (const channel of ["log", "info", "warn", "error", "debug"] as const) {
      vi.spyOn(console, channel).mockImplementation((...args: unknown[]) => output.push(args.map(String).join(" ")));
    }
    const stub = await startStub();
    const { port } = await startGateway({ upstream: `http://127.0.0.1:${stub.port}` });

    await fetch(`http://127.0.0.1:${port}/oauth/nonce`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer private-value" },
      body: '{"pairId":"private-value"}'
    });
    await fetch(`http://127.0.0.1:${port}/oauth/google/callback`, { method: "POST", body: "{}" });

    expect(output).toEqual([]);
  });
});
