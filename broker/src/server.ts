import { createHash, createPublicKey, randomBytes, verify } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { parseBrokerRuntimeConfig } from "./config.js";
import { deviceSigningKeyFingerprint, EnrollmentStore } from "./enrollment-store.js";
import {
  InMemoryEnrollmentRecordStore,
  pairIdHash,
  type EnrollmentRecordStore
} from "./enrollment-record-store.js";
import { GoogleOAuthClient, validateGrantedScope, type OAuthTokenTransport } from "./google-oauth-client.js";
import { sealLease } from "./lease-sealer.js";
import { PairingStore } from "./pairing-store.js";
import type { RefreshTokenStore } from "./refresh-token-store.js";

export interface BrokerServerOptions {
  now?: () => number;
  pairingStore?: PairingStore;
  enrollmentStore?: EnrollmentStore;
  enrollmentRecordStore?: EnrollmentRecordStore;
  enrollmentRecordTtlMs?: number;
  maxPairAttemptsPerWindow?: number;
  rateLimitWindowMs?: number;
  oauth?: {
    config: object;
    clientSecret?: string;
  };
  refreshTokenStore?: RefreshTokenStore;
  oauthTransport?: OAuthTokenTransport;
  /**
   * Unique harmless Drive folder name allowed in device leases. Required: the
   * broker must never invent a default root, because a silent fallback would
   * seal a folder name the operator never chose.
   */
  allowedRootName: string;
  nonceTtlMs?: number;
}

const MAX_JSON_BYTES = 8 * 1024;
const DEFAULT_NONCE_TTL_MS = 120_000;
const DEFAULT_TOKEN_LIFETIME_SECONDS = 3_600;
// Enrolled devices renew leases for a long, bounded window (default 90 days).
const DEFAULT_ENROLLMENT_RECORD_TTL_MS = 90 * 24 * 60 * 60_000;
const MIN_ENROLLMENT_RECORD_TTL_MS = 24 * 60 * 60_000;
const MAX_ENROLLMENT_RECORD_TTL_MS = 365 * 24 * 60 * 60_000;

/** Both callback paths share one handler; only these two are served (exact path match). */
const CALLBACK_PATHS: ReadonlySet<string> = new Set([
  "/oauth/google/callback",
  "/gdrive-stream-oauth/google/callback"
]);

const OAUTH_SUCCESS_PAGE =
  "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
  "<title>Authorization complete</title></head><body>" +
  "<h1>Authorization complete</h1><p>You can now return to your device.</p></body></html>";

const OAUTH_FAILURE_PAGE =
  "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
  "<title>Authorization failed</title></head><body>" +
  "<h1>Authorization failed</h1><p>This sign-in attempt could not be completed. Please start a new pairing.</p></body></html>";

function sendJson(response: ServerResponse, status: number, body: object): void {
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff"
  });
  response.end(JSON.stringify(body));
}

/** Static, non-reflecting HTML page. No request field is ever echoed back. */
function sendHtml(response: ServerResponse, status: number, html: string): void {
  response.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    "content-security-policy": "default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  });
  response.end(html);
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

/**
 * Minimal HTTP boundary. It does not log request bodies and never returns
 * Google codes, states, access tokens, refresh tokens or provider error text.
 * Raw Google access tokens leave only inside a device-sealed lease envelope.
 */
export function createBrokerServer(options: BrokerServerOptions): Server {
  const now = options.now ?? Date.now;
  const oauthConfig = options.oauth ? parseBrokerRuntimeConfig(options.oauth.config as Record<string, unknown>) : undefined;
  const clientSecret = options.oauth?.clientSecret;
  const googleOAuthClient = oauthConfig ? new GoogleOAuthClient(oauthConfig) : undefined;
  const refreshTokenStore = options.refreshTokenStore;
  const oauthTransport = options.oauthTransport;
  const pairingStore = options.pairingStore ?? new PairingStore(undefined, oauthConfig?.pairingCapacity ?? 500);
  const enrollmentStore = options.enrollmentStore ?? new EnrollmentStore();
  const enrollmentRecords = options.enrollmentRecordStore ?? new InMemoryEnrollmentRecordStore();
  const enrollmentRecordTtlMs = options.enrollmentRecordTtlMs ?? DEFAULT_ENROLLMENT_RECORD_TTL_MS;
  const maxPairAttempts = options.maxPairAttemptsPerWindow ?? oauthConfig?.pairingRateLimitMaxAttempts ?? 10;
  const rateLimitWindowMs = options.rateLimitWindowMs ?? oauthConfig?.pairingRateLimitWindowMs ?? 60_000;
  const allowedRootName = options.allowedRootName;
  const nonceTtlMs = options.nonceTtlMs ?? DEFAULT_NONCE_TTL_MS;
  // This validator must stay canonically identical to the plugin's
  // `normalizeAllowedRootName`: a value the plugin would normalise away (a dot
  // segment, a path, an empty string) must be rejected here too, otherwise the
  // broker seals a root the plugin can never match.
  if (
    typeof allowedRootName !== "string" ||
    allowedRootName.trim() === "" ||
    allowedRootName.length > 256 ||
    allowedRootName !== allowedRootName.trim() ||
    /[\u0000-\u001f/\\]/.test(allowedRootName) ||
    allowedRootName === "." ||
    allowedRootName === ".."
  ) {
    throw new Error("Invalid allowed root folder name");
  }
  if (!Number.isInteger(maxPairAttempts) || maxPairAttempts < 1 || !Number.isInteger(rateLimitWindowMs) || rateLimitWindowMs < 1_000) {
    throw new Error("Invalid pairing rate limit configuration");
  }
  if (!Number.isInteger(nonceTtlMs) || nonceTtlMs < 1 || nonceTtlMs > DEFAULT_NONCE_TTL_MS) {
    throw new Error("Invalid nonce TTL configuration");
  }
  if (
    !Number.isInteger(enrollmentRecordTtlMs) ||
    enrollmentRecordTtlMs < MIN_ENROLLMENT_RECORD_TTL_MS ||
    enrollmentRecordTtlMs > MAX_ENROLLMENT_RECORD_TTL_MS
  ) {
    throw new Error("Invalid enrollment record TTL configuration");
  }
  const leaseEndpointReady =
    Boolean(oauthConfig) && Boolean(googleOAuthClient) && Boolean(refreshTokenStore) &&
    typeof clientSecret === "string" && clientSecret.length > 0;

  const attempts = new Map<string, { startedAtMs: number; count: number }>();
  const allowPairAttempt = (clientAddress: string): boolean => {
    const nowMs = now();
    for (const [address, entry] of attempts) {
      if (nowMs - entry.startedAtMs >= rateLimitWindowMs) attempts.delete(address);
    }
    const entry = attempts.get(clientAddress);
    if (!entry) {
      attempts.set(clientAddress, { startedAtMs: nowMs, count: 1 });
      return true;
    }
    if (entry.count >= maxPairAttempts) return false;
    entry.count += 1;
    return true;
  };

  /**
   * Mints a fresh read-only access token, validates the granted scope and seals
   * it to the device encryption key. The raw token exists only inside the sealed
   * envelope and in memory. Returns undefined when no refresh token is stored.
   */
  const mintSealedLease = async (
    deviceEncryptionPublicKeyPem: string
  ): Promise<{ sealedLease: ReturnType<typeof sealLease>; expiresAtMs: number } | undefined> => {
    if (!googleOAuthClient || typeof clientSecret !== "string" || clientSecret.length === 0 || !refreshTokenStore) {
      throw new Error("oauth_unavailable");
    }
    const stored = await refreshTokenStore.read();
    if (!stored) return undefined;
    const tokens = await googleOAuthClient.refreshAccessToken({
      refreshToken: stored.refreshToken,
      clientSecret,
      transport: oauthTransport
    });
    const expiresAtMs = now() + (tokens.expiresIn ?? DEFAULT_TOKEN_LIFETIME_SECONDS) * 1_000;
    const sealedLease = sealLease({
      payload: {
        accessToken: tokens.accessToken,
        expiresAtMs,
        scope: tokens.scope,
        allowedRootName
      },
      deviceEncryptionPublicKeyPem
    });
    return { sealedLease, expiresAtMs };
  };

  /**
   * Short-lived, single-use lease nonces. They are deliberately process-local:
   * a nonce lives at most two minutes, while the durable enrollment record (see
   * the enrollment record store) is what carries authorization across broker
   * restarts and long after the pairing TTL.
   */
  const issuedNonces = new Map<string, { pairIdHash: string; expiresAtMs: number }>();
  const nonceHash = (nonce: string): string => createHash("sha256").update(nonce, "utf8").digest("hex");

  /** True when this process holds the pairing handshake but has not enrolled it yet. */
  const handshakeInProgress = (pairId: string): boolean => {
    const phase = pairingStore.statusOf(pairId);
    return phase === "pending" || phase === "callback_state_consumed" || phase === "authorized";
  };

  /** Issues a nonce bound to a durably enrolled device; unknown or revoked devices fail closed. */
  const issueDurableNonce = async (
    pairId: string
  ): Promise<{ ok: true; nonce: string; expiresAtMs: number } | { ok: false; reason: "not_authorized_yet" | "revoked" }> => {
    if (pairingStore.statusOf(pairId) === "revoked") return { ok: false, reason: "revoked" };
    const record = await enrollmentRecords.find(pairId);
    if (!record || record.revoked || now() >= record.expiresAtMs) {
      return { ok: false, reason: !record && handshakeInProgress(pairId) ? "not_authorized_yet" : "revoked" };
    }
    const nonce = randomBytes(32).toString("base64url");
    const expiresAtMs = now() + nonceTtlMs;
    issuedNonces.set(nonceHash(nonce), { pairIdHash: pairIdHash(pairId), expiresAtMs });
    return { ok: true, nonce, expiresAtMs };
  };

  /**
   * Consumes a nonce atomically against the durable enrollment record: the
   * nonce is deleted before signature verification (so a replay always fails)
   * and the Ed25519 proof is verified against the durable device signing key.
   */
  const consumeDurableNonce = async (input: {
    pairId: string;
    nonce: string;
    proof: string;
  }): Promise<
    | { ok: true; deviceEncryptionPublicKeyPem: string }
    | { ok: false; reason: "not_authorized_yet" | "revoked" | "invalid_nonce" | "invalid_proof" }
  > => {
    if (pairingStore.statusOf(input.pairId) === "revoked") return { ok: false, reason: "revoked" };
    const record = await enrollmentRecords.find(input.pairId);
    if (!record) {
      return { ok: false, reason: handshakeInProgress(input.pairId) ? "not_authorized_yet" : "revoked" };
    }
    if (record.revoked || now() >= record.expiresAtMs) return { ok: false, reason: "revoked" };

    const hash = nonceHash(input.nonce);
    const pending = issuedNonces.get(hash);
    if (!pending || pending.pairIdHash !== pairIdHash(input.pairId)) return { ok: false, reason: "invalid_nonce" };
    issuedNonces.delete(hash);
    if (now() >= pending.expiresAtMs) return { ok: false, reason: "invalid_nonce" };

    let valid = false;
    try {
      const signature = Buffer.from(input.proof, "base64url");
      valid =
        signature.length > 0 &&
        verify(null, Buffer.from(input.nonce, "base64url"), createPublicKey(record.deviceSigningPublicKeyPem), signature);
    } catch {
      valid = false;
    }
    if (!valid) return { ok: false, reason: "invalid_proof" };
    return { ok: true, deviceEncryptionPublicKeyPem: record.deviceEncryptionPublicKeyPem };
  };

  const handleOAuthCallback = async (requestUrl: URL, response: ServerResponse): Promise<void> => {
    const params = requestUrl.searchParams;

    // A provider error redirect must never burn the one-time state.
    if (params.has("error")) {
      sendHtml(response, 400, OAUTH_FAILURE_PAGE);
      return;
    }

    const state = params.get("state");
    const code = params.get("code");
    if (
      !state ||
      !code ||
      !oauthConfig ||
      !googleOAuthClient ||
      !refreshTokenStore ||
      typeof clientSecret !== "string" ||
      clientSecret.length === 0
    ) {
      sendHtml(response, 400, OAUTH_FAILURE_PAGE);
      return;
    }

    const consumed = pairingStore.consumeOAuthState({ oauthState: state, nowMs: now() });
    if (!consumed) {
      sendHtml(response, 400, OAUTH_FAILURE_PAGE);
      return;
    }

    try {
      const tokens = await googleOAuthClient.exchangeAuthorizationCode({
        code,
        codeVerifier: consumed.pkceVerifier,
        clientSecret,
        transport: oauthTransport
      });
      const scope = validateGrantedScope({
        grantedScope: tokens.scope,
        requiredScope: oauthConfig.googleDriveScope,
        allowedScopes: [oauthConfig.googleDriveScope]
      });
      if (tokens.refreshToken) {
        await refreshTokenStore.replace({ refreshToken: tokens.refreshToken, scope, obtainedAtMs: now() });
      } else if (!(await refreshTokenStore.read())) {
        // First enrollment: without a refresh token the broker could never mint
        // a lease for this device. Fail closed and leave the pairing in
        // callback_state_consumed rather than recording a useless approval.
        sendHtml(response, 400, OAUTH_FAILURE_PAGE);
        return;
      }
      // Re-authorization with an existing valid stored record may proceed even
      // when Google omits refresh_token; the stored token is still usable.
      if (!pairingStore.markAuthorized({ callbackHandle: consumed.callbackHandle, nowMs: now() })) {
        sendHtml(response, 400, OAUTH_FAILURE_PAGE);
        return;
      }
      sendHtml(response, 200, OAUTH_SUCCESS_PAGE);
    } catch {
      // Any exchange or persistence failure leaves the pairing in
      // callback_state_consumed; it is never authorized and nothing is reflected.
      sendHtml(response, 400, OAUTH_FAILURE_PAGE);
    }
  };

  return createServer(async (request, response) => {
    try {
      if (request.method === "GET") {
        const requestUrl = new URL(request.url ?? "/", "http://127.0.0.1");
        if (CALLBACK_PATHS.has(requestUrl.pathname)) {
          if (!oauthConfig) {
            sendJson(response, 404, { error: "not_found" });
            return;
          }
          await handleOAuthCallback(requestUrl, response);
          return;
        }
      }
      if (request.method === "GET" && request.url === "/health") {
        sendJson(response, 200, { service: "gdrive-stream-broker", status: "ok" });
        return;
      }
      if (request.method === "POST" && request.url === "/oauth/pair") {
        if (!allowPairAttempt(request.socket.remoteAddress ?? "unknown")) {
          response.setHeader("retry-after", Math.ceil(rateLimitWindowMs / 1_000));
          sendJson(response, 429, { error: "pairing_rate_limited" });
          return;
        }
        if (!request.headers["content-type"]?.startsWith("application/json")) {
          sendJson(response, 415, { error: "json_content_type_required" });
          return;
        }
        const body = await jsonBody(request);
        if (typeof body.devicePublicKeyPem !== "string" || body.devicePublicKeyPem.length > 2_048) {
          sendJson(response, 400, { error: "invalid_device_public_key" });
          return;
        }
        if (typeof body.deviceEncryptionPublicKeyPem !== "string" || body.deviceEncryptionPublicKeyPem.length > 2_048) {
          sendJson(response, 400, { error: "invalid_device_encryption_public_key" });
          return;
        }
        // Device-approval gate: an operator-issued, single-use enrollment code is
        // required before any pairing exists. Failure creates nothing and returns
        // no authorization URL.
        let fingerprint: string;
        try {
          fingerprint = deviceSigningKeyFingerprint(body.devicePublicKeyPem);
        } catch {
          sendJson(response, 400, { error: "invalid_device_public_key" });
          return;
        }
        const enrollment = enrollmentStore.consume({
          code: typeof body.enrollmentCode === "string" ? body.enrollmentCode : "",
          nowMs: now(),
          deviceFingerprint: fingerprint
        });
        if (!enrollment.ok) {
          sendJson(response, 403, { error: "enrollment_required" });
          return;
        }
        const created = pairingStore.create({
          devicePublicKeyPem: body.devicePublicKeyPem,
          deviceEncryptionPublicKeyPem: body.deviceEncryptionPublicKeyPem,
          nowMs: now(),
          ttlMs: oauthConfig?.pairingTtlMs ?? 5 * 60_000,
          authorizationUrlFor: googleOAuthClient
            ? (values) => googleOAuthClient.createAuthorizationUrl(values)
            : undefined
        });
        sendJson(response, 201, {
          pairId: created.pairId,
          oauthState: created.oauthState,
          proofMessage: created.proofMessage,
          expiresAtMs: created.expiresAtMs,
          ...(created.authorizationUrl ? { authorizationUrl: created.authorizationUrl } : {})
        });
        return;
      }

      if (
        request.method === "POST" &&
        (request.url === "/oauth/claim" || request.url === "/oauth/nonce" || request.url === "/oauth/lease")
      ) {
        if (!leaseEndpointReady || !oauthConfig) {
          sendJson(response, 404, { error: "not_found" });
          return;
        }
        if (!request.headers["content-type"]?.startsWith("application/json")) {
          sendJson(response, 415, { error: "json_content_type_required" });
          return;
        }
        const body = await jsonBody(request);
        if (typeof body.pairId !== "string" || body.pairId.length > 256) {
          sendJson(response, 400, { error: "invalid_pair_id" });
          return;
        }

        if (request.url === "/oauth/claim") {
          if (typeof body.proof !== "string" || body.proof.length > 512) {
            sendJson(response, 400, { error: "invalid_proof" });
            return;
          }
          const claimed = pairingStore.openClaim({ pairId: body.pairId, proof: body.proof, nowMs: now() });
          if (!claimed.ok) {
            if (claimed.reason === "expired") sendJson(response, 410, { error: "expired" });
            else if (claimed.reason === "not_authorized_yet") sendJson(response, 409, { error: "not_authorized_yet" });
            else if (claimed.reason === "invalid_proof") sendJson(response, 403, { error: "invalid_proof" });
            else sendJson(response, 403, { error: "revoked" });
            return;
          }
          try {
            // Persist the durable enrollment before any lease is minted so
            // renewal survives a broker restart and the short pairing TTL.
            await enrollmentRecords.record({
              pairId: body.pairId,
              deviceSigningPublicKeyPem: claimed.deviceSigningPublicKeyPem,
              deviceEncryptionPublicKeyPem: claimed.deviceEncryptionPublicKeyPem,
              enrolledAtMs: now(),
              expiresAtMs: now() + enrollmentRecordTtlMs
            });
            const lease = await mintSealedLease(claimed.deviceEncryptionPublicKeyPem);
            if (!lease) {
              sendJson(response, 409, { error: "not_authorized_yet" });
              return;
            }
            sendJson(response, 200, { sealedLease: lease.sealedLease, expiresAtMs: lease.expiresAtMs });
          } catch {
            sendJson(response, 502, { error: "lease_unavailable" });
          }
          return;
        }

        if (request.url === "/oauth/nonce") {
          const issued = await issueDurableNonce(body.pairId);
          if (!issued.ok) {
            if (issued.reason === "not_authorized_yet") sendJson(response, 409, { error: "not_authorized_yet" });
            else sendJson(response, 403, { error: "revoked" });
            return;
          }
          sendJson(response, 200, { nonce: issued.nonce, expiresAtMs: issued.expiresAtMs });
          return;
        }

        // /oauth/lease
        if (typeof body.nonce !== "string" || body.nonce.length > 256 || typeof body.proof !== "string" || body.proof.length > 512) {
          sendJson(response, 403, { error: "invalid_nonce" });
          return;
        }
        const leased = await consumeDurableNonce({ pairId: body.pairId, nonce: body.nonce, proof: body.proof });
        if (!leased.ok) {
          if (leased.reason === "not_authorized_yet") sendJson(response, 409, { error: "not_authorized_yet" });
          else if (leased.reason === "invalid_nonce") sendJson(response, 403, { error: "invalid_nonce" });
          else if (leased.reason === "invalid_proof") sendJson(response, 403, { error: "invalid_proof" });
          else sendJson(response, 403, { error: "revoked" });
          return;
        }
        try {
          const lease = await mintSealedLease(leased.deviceEncryptionPublicKeyPem);
          if (!lease) {
            sendJson(response, 409, { error: "not_authorized_yet" });
            return;
          }
          sendJson(response, 200, { sealedLease: lease.sealedLease, expiresAtMs: lease.expiresAtMs });
        } catch {
          sendJson(response, 502, { error: "lease_unavailable" });
        }
        return;
      }

      sendJson(response, 404, { error: "not_found" });
    } catch {
      // Deliberately avoid reflecting malformed input, key material or body data.
      sendJson(response, 400, { error: "invalid_request" });
    }
  });
}
