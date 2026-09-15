import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";

/**
 * Private API gateway for the private network Serve mount. It deliberately exposes only
 * the four mobile pairing endpoints; OAuth callbacks, health and every other
 * broker route remain outside this gateway.
 */
export interface PrivateApiGatewayOptions {
  /** Loopback HTTP base URL of the broker core. */
  upstream?: string;
  /** Bounded upstream request timeout in milliseconds. */
  timeoutMs?: number;
}

export interface StartPrivateApiGatewayOptions extends PrivateApiGatewayOptions {
  /** Loopback port to bind; 0 asks the kernel for an ephemeral port. */
  port: number;
}

const DEFAULT_UPSTREAM = "http://127.0.0.1:34003";
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const MAX_BODY_BYTES = 8 * 1024;
const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "::1", "localhost"]);
const LOOPBACK_BIND_ADDRESS = "127.0.0.1";
const ALLOWED_PATHS = new Set(["/oauth/pair", "/oauth/claim", "/oauth/nonce", "/oauth/lease"]);

type BodyReadResult = { kind: "body"; body: Buffer } | { kind: "invalid" } | { kind: "too_large" };

function configError(detail: string): Error {
  return new Error(`Private API gateway configuration error: ${detail}`);
}

function normaliseLoopbackUpstream(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw configError("upstream must be a loopback http URL");
  }
  if (url.protocol !== "http:") throw configError("upstream must be a loopback http URL");
  const hostname = url.hostname.replace(/^\[/, "").replace(/\]$/, "").toLowerCase();
  if (!LOOPBACK_HOSTNAMES.has(hostname)) throw configError("upstream must be a loopback http URL");
  return url;
}

function normaliseTimeout(value: number | undefined): number {
  const timeoutMs = value ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_TIMEOUT_MS) {
    throw configError("timeoutMs must be an integer between 1 and 60000");
  }
  return timeoutMs;
}

function sendJson(response: ServerResponse, status: number, body: object): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

function hasJsonContentType(request: IncomingMessage): boolean {
  const contentType = request.headers["content-type"];
  return typeof contentType === "string" && /^application\/json(?:\s*;|\s*$)/i.test(contentType);
}

/** Reads a body locally before any upstream connection is opened. */
async function readJsonBody(request: IncomingMessage): Promise<BodyReadResult> {
  const contentLength = request.headers["content-length"];
  if (typeof contentLength === "string" && /^\d+$/.test(contentLength) && Number.parseInt(contentLength, 10) > MAX_BODY_BYTES) {
    request.resume();
    return { kind: "too_large" };
  }
  if (typeof contentLength === "string" && !/^\d+$/.test(contentLength)) {
    request.resume();
    return { kind: "invalid" };
  }

  return new Promise<BodyReadResult>((resolve) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let settled = false;
    const finish = (result: BodyReadResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    request.on("data", (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > MAX_BODY_BYTES) {
        finish({ kind: "too_large" });
        request.resume();
        return;
      }
      chunks.push(buffer);
    });
    request.on("aborted", () => finish({ kind: "invalid" }));
    request.on("error", () => finish({ kind: "invalid" }));
    request.on("end", () => {
      if (settled) return;
      const body = Buffer.concat(chunks);
      try {
        JSON.parse(body.toString("utf8"));
      } catch {
        finish({ kind: "invalid" });
        return;
      }
      finish({ kind: "body", body });
    });
  });
}

export function createPrivateApiGateway(options: PrivateApiGatewayOptions = {}): Server {
  const upstream = normaliseLoopbackUpstream(options.upstream ?? DEFAULT_UPSTREAM);
  const timeoutMs = normaliseTimeout(options.timeoutMs);
  const upstreamHost = upstream.hostname.replace(/^\[/, "").replace(/\]$/, "");
  const upstreamPort = upstream.port.length > 0 ? Number.parseInt(upstream.port, 10) : 80;

  const forward = (clientResponse: ServerResponse, path: string, body: Buffer): void => {
    let settled = false;
    const fail = (): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (clientResponse.headersSent) clientResponse.destroy();
      else sendJson(clientResponse, 502, { error: "upstream_unavailable" });
    };
    const deadline = setTimeout(fail, timeoutMs);
    const upstreamRequest = httpRequest(
      {
        host: upstreamHost,
        port: upstreamPort,
        method: "POST",
        path,
        headers: { "content-type": "application/json" },
        timeout: timeoutMs
      },
      (upstreamResponse) => {
        if (settled) {
          upstreamResponse.destroy();
          return;
        }
        settled = true;
        clearTimeout(deadline);
        clientResponse.writeHead(upstreamResponse.statusCode ?? 502, {
          "content-type": upstreamResponse.headers["content-type"] ?? "application/json; charset=utf-8",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff"
        });
        upstreamResponse.on("error", () => clientResponse.destroy());
        upstreamResponse.pipe(clientResponse);
      }
    );
    upstreamRequest.on("timeout", () => upstreamRequest.destroy(new Error("upstream_timeout")));
    upstreamRequest.on("error", fail);
    clientResponse.on("close", () => {
      if (!clientResponse.writableEnded) upstreamRequest.destroy();
    });
    upstreamRequest.end(body);
  };

  return createServer(async (request, response) => {
    // Exact raw URL matching prevents query, prefix and callback-path bypasses.
    const path = request.url ?? "/";
    if (request.method !== "POST" || !ALLOWED_PATHS.has(path)) {
      request.resume();
      sendJson(response, 404, { error: "not_found" });
      return;
    }
    if (!hasJsonContentType(request)) {
      request.resume();
      sendJson(response, 400, { error: "invalid_request" });
      return;
    }

    const read = await readJsonBody(request);
    if (read.kind === "too_large") {
      sendJson(response, 413, { error: "payload_too_large" });
      return;
    }
    if (read.kind === "invalid") {
      sendJson(response, 400, { error: "invalid_request" });
      return;
    }
    forward(response, path, read.body);
  });
}

/** Creates the private gateway and binds it to 127.0.0.1 only. */
export async function startPrivateApiGateway(options: StartPrivateApiGatewayOptions): Promise<Server> {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535) {
    throw configError("port must be a user-space TCP port");
  }
  const server = createPrivateApiGateway(options);
  await new Promise<void>((resolveListen, rejectListen) => {
    const onError = (error: Error): void => {
      server.off("listening", onListening);
      rejectListen(error);
    };
    const onListening = (): void => {
      server.off("error", onError);
      resolveListen();
    };
    server.once("error", onError);
    server.once("listening", onListening);
    server.listen(options.port, LOOPBACK_BIND_ADDRESS);
  });
  return server;
}
