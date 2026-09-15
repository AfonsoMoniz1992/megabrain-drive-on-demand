import type { BrokerClient, LeaseResult } from "./broker-client";
import { BrokerError } from "./broker-client";
import { BETA_ROOT_FOLDER_NAME } from "../drive/root-scope";
import {
  exportEd25519SpkiPem,
  exportX25519SpkiPem,
  signUtf8Base64Url,
  unsealLease,
  type DeviceIdentity
} from "./device-identity";

/**
 * Device enrollment and transparent lease renewal.
 *
 * The Google access token lives in a private field for the lifetime of this
 * object only; it is never returned to persistent storage, never logged and
 * never included in the enrollment state emitted to the UI. Enrollment state
 * (pair id + expiry) is deliberately non-secret so the plugin may persist it.
 */

export const DEFAULT_ROOT_FOLDER_NAME = BETA_ROOT_FOLDER_NAME;
export const DEFAULT_CLAIM_POLL_INTERVAL_MS = 2_000;
export const DEFAULT_RENEWAL_LEAD_MS = 60_000;

export type EnrollmentStatus = "not_enrolled" | "enrolled";

export interface EnrollmentView {
  pairId: string | null;
  status: EnrollmentStatus;
  expiresAtMs: number | null;
}

export interface LeaseView {
  expiresAtMs: number;
  scope: string;
  allowedRootName: string;
}

export interface LeaseManagerOptions {
  broker: BrokerClient;
  identity: DeviceIdentity;
  /** Opens the Google consent URL in the system browser. */
  openAuthorizationUrl: (url: string) => void | Promise<void>;
  rootFolderName?: string;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  claimPollIntervalMs?: number;
  renewalLeadMs?: number;
  /** Persisted, non-secret enrollment state. */
  initialPairId?: string | null;
  /** Reports non-secret enrollment state changes for persistence/UI. */
  onEnrollment?: (state: EnrollmentView) => void;
}

const defaultSleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

export class LeaseManager {
  private readonly broker: BrokerClient;
  private readonly identity: DeviceIdentity;
  private readonly openAuthorizationUrl: (url: string) => void | Promise<void>;
  private readonly rootFolderName: string;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly claimPollIntervalMs: number;
  private readonly renewalLeadMs: number;
  private readonly onEnrollment?: (state: EnrollmentView) => void;

  private pairId: string | null;
  private accessToken: string | null = null;
  private accessTokenExpiresAtMs = 0;
  private lease: LeaseView | null = null;
  private renewal: Promise<LeaseView> | null = null;

  constructor(options: LeaseManagerOptions) {
    this.broker = options.broker;
    this.identity = options.identity;
    this.openAuthorizationUrl = options.openAuthorizationUrl;
    this.rootFolderName = options.rootFolderName ?? DEFAULT_ROOT_FOLDER_NAME;
    if (!this.rootFolderName) throw new Error("A beta root folder name is required");
    this.now = options.now ?? Date.now;
    this.sleep = options.sleep ?? defaultSleep;
    this.claimPollIntervalMs = options.claimPollIntervalMs ?? DEFAULT_CLAIM_POLL_INTERVAL_MS;
    if (!Number.isFinite(this.claimPollIntervalMs) || this.claimPollIntervalMs <= 0) throw new Error("Claim poll interval is invalid");
    this.renewalLeadMs = options.renewalLeadMs ?? DEFAULT_RENEWAL_LEAD_MS;
    if (!Number.isFinite(this.renewalLeadMs) || this.renewalLeadMs < 0) throw new Error("Renewal lead time is invalid");
    this.onEnrollment = options.onEnrollment;
    this.pairId = options.initialPairId ?? null;
  }

  get enrollment(): EnrollmentView {
    // A persisted pairId means the device is still paired: after a plugin
    // restart the lease is simply missing, so it is reported as enrolled and
    // renewed on next use rather than forcing a full re-enrollment.
    return { pairId: this.pairId, status: this.lease || this.pairId ? "enrolled" : "not_enrolled", expiresAtMs: this.lease ? this.lease.expiresAtMs : null };
  }

  /** True only while a device-bound lease is still usable without renewal. */
  get enrolled(): boolean {
    return this.lease !== null;
  }

  hasValidLease(): boolean {
    return this.lease !== null && this.now() < this.accessTokenExpiresAtMs - this.renewalLeadMs;
  }

  leaseView(): LeaseView | null {
    return this.lease ? { ...this.lease } : null;
  }

  /** Forgets the pairing and the in-memory token (logout / revocation). */
  clear(): void {
    this.pairId = null;
    this.accessToken = null;
    this.accessTokenExpiresAtMs = 0;
    this.lease = null;
    this.renewal = null;
    this.emit();
  }

  /**
   * Full enrollment: pair with the one-time code, open Google consent in the
   * system browser, then poll `/oauth/claim` until consent completes.
   */
  async enroll(enrollmentCode: string): Promise<LeaseView> {
    const code = enrollmentCode.trim();
    if (!code) throw new Error("An enrollment code is required");
    const pair = await this.broker.pair({
      enrollmentCode: code,
      devicePublicKeyPem: exportEd25519SpkiPem(this.identity.ed25519PublicKey),
      deviceEncryptionPublicKeyPem: exportX25519SpkiPem(this.identity.x25519PublicKey)
    });
    this.pairId = pair.pairId;
    this.emit(pair.expiresAtMs);
    await this.openAuthorizationUrl(pair.authorizationUrl);
    const claim = await this.claimUntilAuthorized(pair.pairId, pair.proofMessage, pair.expiresAtMs);
    try {
      return this.applyLease(claim);
    } catch (error) {
      // A lease for a foreign root is never usable; drop the pairing entirely.
      this.clear();
      throw error;
    }
  }

  private async claimUntilAuthorized(pairId: string, proofMessage: string, expiresAtMs: number): Promise<LeaseResult> {
    const proof = signUtf8Base64Url(this.identity, proofMessage);
    const maxAttempts = Math.max(1, Math.ceil((expiresAtMs - this.now()) / this.claimPollIntervalMs) + 1);
    for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
      if (this.now() >= expiresAtMs) break;
      try {
        return await this.broker.claim({ pairId, proof });
      } catch (error) {
        if (!(error instanceof BrokerError) || error.code !== "not_authorized_yet") throw error;
        await this.sleep(this.claimPollIntervalMs);
      }
    }
    this.pairId = null;
    this.emit();
    throw new BrokerError("expired", 410);
  }

  /** Renews through `/oauth/nonce` + `/oauth/lease`; never re-runs consent. */
  async refreshLease(): Promise<LeaseView> {
    if (this.renewal) return this.renewal;
    this.renewal = this.performRenewal().finally(() => { this.renewal = null; });
    return this.renewal;
  }

  private async performRenewal(): Promise<LeaseView> {
    const pairId = this.pairId;
    if (!pairId) throw new BrokerError("not_enrolled");
    try {
      const { nonce } = await this.broker.nonce({ pairId });
      const proof = signUtf8Base64Url(this.identity, nonce);
      const lease = await this.broker.lease({ pairId, nonce, proof });
      return this.applyLease(lease);
    } catch (error) {
      if (error instanceof BrokerError && (error.code === "revoked" || error.code === "expired")) this.clear();
      throw error;
    }
  }

  /** Returns a usable bearer token, renewing shortly before expiry. */
  async getValidAccessToken(): Promise<string> {
    if (!this.pairId) throw new BrokerError("not_enrolled");
    if (this.accessToken && this.hasValidLease()) return this.accessToken;
    await this.refreshLease();
    if (!this.accessToken) throw new BrokerError("not_enrolled");
    return this.accessToken;
  }

  private applyLease(result: LeaseResult): LeaseView {
    const payload = unsealLease(this.identity, result.sealedLease);
    if (payload.allowedRootName !== this.rootFolderName) {
      throw new Error(`Lease is not scoped to the ${this.rootFolderName} root folder`);
    }
    const view: LeaseView = { expiresAtMs: payload.expiresAtMs, scope: payload.scope, allowedRootName: payload.allowedRootName };
    this.accessToken = payload.accessToken;
    this.accessTokenExpiresAtMs = payload.expiresAtMs;
    this.lease = view;
    this.emit();
    return { ...view };
  }

  private emit(expiresAtMs?: number): void {
    this.onEnrollment?.({
      pairId: this.pairId,
      status: this.lease ? "enrolled" : "not_enrolled",
      expiresAtMs: expiresAtMs ?? (this.lease ? this.lease.expiresAtMs : null)
    });
  }
}
