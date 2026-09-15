import {
  createServer,
  request as httpRequest,
  type Server,
  type ServerResponse
} from "node:http";

/**
 * Public gateway: the ONLY broker surface a public reverse proxy may reach.
 *
 * Deployment shape: a a private network public reverse proxy path mount strips its prefix (for
 * example `/gdrive-stream-oauth`) before forwarding, so a public request to
 * `https://<host>/gdrive-stream-oauth/google/callback` arrives here as
 * `/google/callback`. This server forwards that ONE exact path to the
 * loopback broker (rewriting it to the broker's registered callback route) and
 * answers a bare 404 for everything else, in particular `/health`,
 * `/oauth/pair`, `/oauth/claim`, `/oauth/nonce` and `/oauth/lease`, which stay
 * reachable only from the loopback network.
 *
 * Deliberate limits:
 *  - only GET is forwarded; the whitelisted path rejects other methods (405)
 *    and every other path is 404, GET or POST;
 *  - only the query string travels upstream (state, code, error); the request
 *    body and every client header (cookies included) are dropped;
 *  - the upstream call is bounded by a timeout and any failure becomes a bare
 *    502 with no internal detail;
 *  - nothing is ever logged: no request line, query parameter, state, code,
 *    token or header value is written to any console channel.
 */

export interface PublicGatewayOptions {
  /** Loopback base URL of the broker. Must be an `http:` loopback origin. */
  upstream?: string;
  /** Exact publicly reachable path (the public reverse proxy path mount's remainder). */
  publicPath?: string;
  /** Broker route the public path is rewritten to. */
  upstreamPath?: string;
  /** Bounded upstream request timeout in milliseconds. */
  timeoutMs?: number;
}

export interface StartPublicGatewayOptions extends PublicGatewayOptions {
  /** Loopback port to bind; 0 asks the kernel for an ephemeral port. */
  port: number;
}

const DEFAULT_UPSTREAM = "http://127.0.0.1:34003";
const DEFAULT_PUBLIC_PATH = "/google/callback";
const DEFAULT_UPSTREAM_PATH = "/oauth/google/callback";
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_TIMEOUT_MS = 60_000;
const LOOPBACK_HOSTNAMES = new Set(["127.0.0.1", "::1", "localhost"]);
const LOOPBACK_BIND_ADDRESS = "127.0.0.1";

function configError(detail: string): Error {
  return new Error(`Public gateway configuration error: ${detail}`);
}

/**
 * Accepts only `http://` URLs whose host is literally a loopback name: an
 * interface address, a tunnel host or any other origin is refused so a
 * misconfiguration can never turn this gateway into a proxy to a third party.
 */
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

function normalisePath(value: string | undefined, fallback: string): string {
  const path = value ?? fallback;
  if (
    typeof path !== "string" ||
    !path.startsWith("/") ||
    path.length < 2 ||
    path.includes("?") ||
    path.includes("#")
  ) {
    throw configError("path must be an absolute path without a query or fragment");
  }
  return path;
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

export function createPublicGateway(options: PublicGatewayOptions = {}): Server {
  const upstream = normaliseLoopbackUpstream(options.upstream ?? DEFAULT_UPSTREAM);
  const publicPath = normalisePath(options.publicPath, DEFAULT_PUBLIC_PATH);
  const upstreamPath = normalisePath(options.upstreamPath, DEFAULT_UPSTREAM_PATH);
  const timeoutMs = normaliseTimeout(options.timeoutMs);
  const upstreamHost = upstream.hostname.replace(/^\[/, "").replace(/\]$/, "");
  const upstreamPort = upstream.port.length > 0 ? Number.parseInt(upstream.port, 10) : 80;

  /**
   * Forwards one GET to the broker callback route. The only thing carried over
   * is the raw query string; the response status and body are passed through.
   */
  const forward = (clientResponse: ServerResponse, targetPath: string): void => {
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
        method: "GET",
        path: targetPath,
        headers: { accept: "text/html,application/xhtml+xml" },
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
          "content-type": upstreamResponse.headers["content-type"] ?? "text/html; charset=utf-8",
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
    upstreamRequest.end();
  };

  return createServer((request, response) => {
    // The client request body is never read: draining it (and nothing else)
    // keeps a keep-alive connection usable without forwarding any payload.
    request.resume();

    const rawUrl = request.url ?? "/";
    const queryIndex = rawUrl.indexOf("?");
    const pathname = queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex);
    const search = queryIndex === -1 ? "" : rawUrl.slice(queryIndex);

    // Exact pathname match only: `/google/callback/extra` is not the callback.
    if (pathname !== publicPath) {
      sendJson(response, 404, { error: "not_found" });
      return;
    }
    if (request.method !== "GET") {
      sendJson(response, 405, { error: "method_not_allowed" });
      return;
    }
    forward(response, `${upstreamPath}${search}`);
  });
}

/** Creates the gateway and binds it to 127.0.0.1 only. */
export async function startPublicGateway(options: StartPublicGatewayOptions): Promise<Server> {
  if (!Number.isInteger(options.port) || options.port < 0 || options.port > 65_535) {
    throw configError("port must be a user-space TCP port");
  }
  const server = createPublicGateway(options);
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
    // Loopback only: the public reverse proxy path mount is what makes the callback public.
    server.listen(options.port, LOOPBACK_BIND_ADDRESS);
  });
  return server;
}
