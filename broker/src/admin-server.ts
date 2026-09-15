import { createHash, timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { EnrollmentStore } from "./enrollment-store.js";
import type { EnrollmentRecordStore } from "./enrollment-record-store.js";
import type { PairingStore } from "./pairing-store.js";
import type { RefreshTokenStore } from "./refresh-token-store.js";

/**
 * Operator-only admin surface.
 *
 * This factory is intended to listen on a distinct loopback port that is never
 * publicly proxied. Every request must carry `Authorization: Bearer <token>`
 * matching an injected admin token; the comparison is timing-safe and a
 * missing/invalid token yields 401 with no side effects. The token and any
 * enrollment code are never logged.
 */
export interface AdminServerOptions {
  adminToken: string;
  enrollmentStore: EnrollmentStore;
  enrollmentRecordStore?: EnrollmentRecordStore;
  pairingStore: PairingStore;
  refreshTokenStore?: RefreshTokenStore;
  now?: () => number;
  enrollmentTtlMs?: number;
}

const DEFAULT_ENROLLMENT_TTL_MS = 10 * 60_000;
const MAX_JSON_BYTES = 8 * 1024;

function sendJson(response: ServerResponse, status: number, body: object): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

/**
 * Timing-safe token comparison. Both sides are hashed first so that inputs of
 * differing length compare in constant time and the raw token never lands in a
 * buffer that could be length-timed.
 */
function tokenMatches(provided: string | undefined, expected: string): boolean {
  if (typeof provided !== "string" || provided.length === 0) return false;
  const providedDigest = createHash("sha256").update(provided, "utf8").digest();
  const expectedDigest = createHash("sha256").update(expected, "utf8").digest();
  return timingSafeEqual(providedDigest, expectedDigest);
}

function bearerToken(request: IncomingMessage): string | undefined {
  const header = request.headers.authorization;
  if (typeof header !== "string") return undefined;
  const match = /^Bearer[ ]+(.+)$/i.exec(header.trim());
  return match ? match[1] : undefined;
}

async function jsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    total += bytes.length;
    if (total > MAX_JSON_BYTES) throw new Error("request_too_large");
    chunks.push(bytes);
  }
  const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid_json");
  return parsed as Record<string, unknown>;
}

export function createAdminServer(options: AdminServerOptions): Server {
  if (typeof options.adminToken !== "string" || options.adminToken.length < 16) {
    throw new Error("Admin token is required");
  }
  const adminToken = options.adminToken;
  const now = options.now ?? Date.now;
  const enrollmentTtlMs = options.enrollmentTtlMs ?? DEFAULT_ENROLLMENT_TTL_MS;

  return createServer(async (request, response) => {
    try {
      if (!tokenMatches(bearerToken(request), adminToken)) {
        sendJson(response, 401, { error: "unauthorized" });
        return;
      }

      if (request.method === "POST" && request.url === "/admin/enrollment") {
        if (!request.headers["content-type"]?.startsWith("application/json")) {
          sendJson(response, 415, { error: "json_content_type_required" });
          return;
        }
        const body = await jsonBody(request);
        const fingerprint = body.deviceFingerprint;
        // Fail closed: a code is never minted without the operator-approved
        // device signing-key fingerprint it must be pre-bound to.
        if (typeof fingerprint !== "string" || !/^[0-9a-f]{64}$/i.test(fingerprint.trim())) {
          sendJson(response, 400, { error: "invalid_device_fingerprint" });
          return;
        }
        const issued = options.enrollmentStore.issue({
          nowMs: now(),
          ttlMs: enrollmentTtlMs,
          expectedDeviceFingerprint: fingerprint.trim().toLowerCase()
        });
        // The code is returned exactly once, at mint time.
        sendJson(response, 201, { code: issued.code, expiresAtMs: issued.expiresAtMs });
        return;
      }

      if (request.method === "GET" && request.url === "/admin/enrollment") {
        sendJson(response, 200, options.enrollmentStore.debugCounts());
        return;
      }

      if (request.method === "POST" && request.url === "/admin/revoke") {
        if (!request.headers["content-type"]?.startsWith("application/json")) {
          sendJson(response, 415, { error: "json_content_type_required" });
          return;
        }
        const body = await jsonBody(request);
        if (typeof body.pairId !== "string" || body.pairId.length > 256) {
          sendJson(response, 400, { error: "invalid_pair_id" });
          return;
        }
        const revokedPairing = options.pairingStore.revoke({ pairId: body.pairId, nowMs: now() });
        // Revocation must also be durable: after a restart the ephemeral
        // handshake store is empty, so the enrolled record is the only place
        // that can keep refusing the device.
        const revokedEnrollment = (await options.enrollmentRecordStore?.revoke(body.pairId)) ?? false;
        const revoked = revokedPairing || revokedEnrollment;
        if (revoked) await options.refreshTokenStore?.clear();
        sendJson(response, 200, { revoked });
        return;
      }

      sendJson(response, 404, { error: "not_found" });
    } catch {
      sendJson(response, 400, { error: "invalid_request" });
    }
  });
}
