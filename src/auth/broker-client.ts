import { validateBrokerBaseUrl } from "./mobile-pairing";
import type { SealedEnvelope } from "./device-identity";

/**
 * Typed client for the operator-hosted pairing broker.
 *
 * This module performs the OAuth pairing and short-lived lease handshake. It
 * deliberately contains no logging: pairing responses, nonces, proofs and
 * sealed leases must never reach a console, a diagnostics dump or plugin data.
 * Google is never contacted here — the broker owns the Google credentials.
 */

export interface BrokerRequest {
  url: string;
  method: "POST";
  headers: Record<string, string>;
  body: string;
  throw: false;
}

export interface BrokerResponse {
  status: number;
  json?: unknown;
}

/** Injected transport. The plugin passes Obsidian's `requestUrl`. */
export type BrokerRequestFn = (request: BrokerRequest) => Promise<BrokerResponse>;

export type BrokerErrorCode =
  | "enrollment_required"
  | "not_authorized_yet"
  | "revoked"
  | "expired"
  | "not_enrolled"
  | "unexpected_status"
  | "invalid_response"
  | "transport";

/** Errors carry only a code and an HTTP status — never a server body or secret. */
export class BrokerError extends Error {
  constructor(readonly code: BrokerErrorCode, readonly status?: number) {
    super(status === undefined ? `broker ${code}` : `broker ${code} (${status})`);
    this.name = "BrokerError";
  }
}

export interface PairRequest {
  enrollmentCode: string;
  devicePublicKeyPem: string;
  deviceEncryptionPublicKeyPem: string;
}

export interface PairResult {
  pairId: string;
  oauthState: string;
  proofMessage: string;
  expiresAtMs: number;
  authorizationUrl: string;
}

export interface ClaimRequest {
  pairId: string;
  proof: string;
}

export interface NonceRequest {
  pairId: string;
}

export interface LeaseRequest {
  pairId: string;
  nonce: string;
  proof: string;
}

export interface NonceResult {
  nonce: string;
  expiresAtMs: number;
}

export interface LeaseResult {
  sealedLease: SealedEnvelope;
  expiresAtMs: number;
}

export interface BrokerClientOptions {
  baseUrl: string;
  request: BrokerRequestFn;
}

/** Status-to-code mapping per endpoint, as specified by the broker contract. */
const PAIR_ERROR_CODES: Record<number, BrokerErrorCode> = { 403: "enrollment_required" };
const CLAIM_ERROR_CODES: Record<number, BrokerErrorCode> = { 409: "not_authorized_yet", 403: "revoked", 410: "expired" };
const LEASE_ERROR_CODES: Record<number, BrokerErrorCode> = { 409: "not_authorized_yet", 403: "revoked", 410: "expired" };
const NONCE_ERROR_CODES: Record<number, BrokerErrorCode> = { 403: "revoked", 410: "expired" };

function requireString(record: Record<string, unknown>, field: string): string {
  const value = record[field];
  if (typeof value !== "string" || value.length === 0) throw new BrokerError("invalid_response");
  return value;
}

function requireNumber(record: Record<string, unknown>, field: string): number {
  const value = record[field];
  if (typeof value !== "number" || !Number.isFinite(value)) throw new BrokerError("invalid_response");
  return value;
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new BrokerError("invalid_response");
  return value as Record<string, unknown>;
}

/** Never accept an authorization URL that already carries Google material. */
const FORBIDDEN_URL_MATERIAL = ["access_token", "refresh_token", "client_secret", "code="];

function requireAuthorizationUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new BrokerError("invalid_response");
  }
  if (url.protocol !== "https:") throw new BrokerError("invalid_response");
  const lowered = value.toLowerCase();
  if (FORBIDDEN_URL_MATERIAL.some((needle) => lowered.includes(needle))) throw new BrokerError("invalid_response");
  return value;
}

/** Accepts either an object envelope or its JSON-string encoding. */
export function parseSealedLease(value: unknown): SealedEnvelope {
  let candidate: unknown = value;
  if (typeof candidate === "string") {
    try {
      candidate = JSON.parse(candidate);
    } catch {
      throw new BrokerError("invalid_response");
    }
  }
  const record = asRecord(candidate);
  const envelope: SealedEnvelope = {
    v: requireNumber(record, "v"),
    epk: requireString(record, "epk"),
    salt: requireString(record, "salt"),
    nonce: requireString(record, "nonce"),
    ct: requireString(record, "ct")
  };
  if (envelope.v !== 1) throw new BrokerError("invalid_response");
  return envelope;
}

export class BrokerClient {
  readonly baseUrl: string;
  private readonly request: BrokerRequestFn;

  constructor(options: BrokerClientOptions) {
    this.baseUrl = validateBrokerBaseUrl(options.baseUrl);
    if (typeof options.request !== "function") throw new Error("A broker transport is required");
    this.request = options.request;
  }

  private async post(path: string, body: Record<string, unknown>, codes: Record<number, BrokerErrorCode>): Promise<Record<string, unknown>> {
    let response: BrokerResponse;
    try {
      response = await this.request({
        url: `${this.baseUrl}/oauth/${path}`,
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        throw: false
      });
    } catch {
      throw new BrokerError("transport");
    }
    const mapped = codes[response.status];
    if (mapped) throw new BrokerError(mapped, response.status);
    if (response.status < 200 || response.status >= 300) throw new BrokerError("unexpected_status", response.status);
    return asRecord(response.json);
  }

  async pair(input: PairRequest): Promise<PairResult> {
    const body = await this.post("pair", {
      enrollmentCode: input.enrollmentCode,
      devicePublicKeyPem: input.devicePublicKeyPem,
      deviceEncryptionPublicKeyPem: input.deviceEncryptionPublicKeyPem
    }, PAIR_ERROR_CODES);
    return {
      pairId: requireString(body, "pairId"),
      oauthState: requireString(body, "oauthState"),
      proofMessage: requireString(body, "proofMessage"),
      expiresAtMs: requireNumber(body, "expiresAtMs"),
      authorizationUrl: requireAuthorizationUrl(requireString(body, "authorizationUrl"))
    };
  }

  async claim(input: ClaimRequest): Promise<LeaseResult> {
    const body = await this.post("claim", { pairId: input.pairId, proof: input.proof }, CLAIM_ERROR_CODES);
    return { sealedLease: parseSealedLease(body.sealedLease), expiresAtMs: requireNumber(body, "expiresAtMs") };
  }

  async nonce(input: NonceRequest): Promise<NonceResult> {
    const body = await this.post("nonce", { pairId: input.pairId }, NONCE_ERROR_CODES);
    return { nonce: requireString(body, "nonce"), expiresAtMs: requireNumber(body, "expiresAtMs") };
  }

  async lease(input: LeaseRequest): Promise<LeaseResult> {
    const body = await this.post("lease", { pairId: input.pairId, nonce: input.nonce, proof: input.proof }, LEASE_ERROR_CODES);
    return { sealedLease: parseSealedLease(body.sealedLease), expiresAtMs: requireNumber(body, "expiresAtMs") };
  }
}
