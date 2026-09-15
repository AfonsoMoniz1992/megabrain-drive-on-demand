import type { EnrollmentView } from "../auth/lease-manager";
import { DEFAULT_MAX_DOWNLOAD_BYTES } from "../drive/drive-read-client";
import { MetadataIndex, type IndexedMetadata } from "../drive/metadata-index";
import type { DriveRootScope } from "../drive/root-scope";

/**
 * Read-only browser state for the mobile beta.
 *
 * This module is the layer the Obsidian ItemView renders. It has no DOM and no
 * `obsidian` import so the beta's product rules can be tested directly:
 *
 *  - nothing is reachable before enrollment (no Drive request is attempted);
 *  - only the operator-configured root and its registered descendants are browsable;
 *  - listing/searching return metadata only — content leaves Drive solely
 *    through an explicit, size-capped `download` of one file;
 *  - there is no create, rename, move, delete, trash, copy or upload affordance.
 */

export const BETA_DOWNLOAD_LIMIT_BYTES = DEFAULT_MAX_DOWNLOAD_BYTES;

export type BrowserStatus = "not_enrolled" | "awaiting_consent" | "enrolled";

/**
 * Single source of truth for the status wording shown to an operator. Never
 * upgrade this to say "Enrolled" for a state that still lacks a lease: the
 * earlier unconditional "Enrolled" on a bare pairing made a device look
 * authorised while Google consent had not been granted yet.
 */
export function describeEnrollmentLabel(status: BrowserStatus): string {
  if (status === "enrolled") return "Enrolled";
  if (status === "awaiting_consent") return "Waiting for Google consent";
  return "Not enrolled";
}

export interface BrowserViewState {
  status: BrowserStatus;
  canBrowse: boolean;
  canEnroll: boolean;
  fingerprint: string;
  pairId: string | null;
  expiresAtMs: number | null;
  reason: string;
}

/**
 * Non-secret enrollment summary the settings tab and browser view display.
 * `rootName` is the operator-configured root the lease is scoped to, so the
 * diagnostics name the folder actually in use rather than a hard-coded default.
 */
export function describeBrowserState(enrollment: EnrollmentView, fingerprint: string, rootName: string): BrowserViewState {
  const enrolled = enrollment.status === "enrolled" && Boolean(enrollment.pairId);
  const awaitingConsent = enrollment.status === "awaiting_consent";
  return {
    status: enrolled ? "enrolled" : awaitingConsent ? "awaiting_consent" : "not_enrolled",
    canBrowse: enrolled,
    canEnroll: !enrolled && !awaitingConsent,
    fingerprint,
    pairId: enrollment.pairId,
    expiresAtMs: enrollment.expiresAtMs,
    reason: enrolled
      ? `Enrolled read-only. Browsing is limited to the ${rootName} folder.`
      : awaitingConsent
        ? "Paired, waiting for Google consent. Approve read-only access in the browser window that just opened; nothing is readable until that approval returns."
        : "Not enrolled. Enter a one-time enrollment code to authorise this device, then approve access in the browser."
  };
}

/** Minimal Drive surface the browser needs; structurally satisfied by DriveReadClient. */
export interface BrowserDriveSource {
  listChildren(parentId: string): Promise<{ files: IndexedMetadata[]; nextPageToken?: string }>;
  downloadFile(fileId: string): Promise<{ fileId: string; name: string; mimeType: string; bytes: Uint8Array }>;
}

export interface BrowserControllerOptions {
  source: BrowserDriveSource;
  scope: DriveRootScope;
  index: MetadataIndex;
  enrollment: () => EnrollmentView;
  /** Canonical 64-character device enrollment fingerprint shown alongside the enrollment state. */
  fingerprint?: () => string;
  maxDownloadBytes?: number;
}

export class BrowserController {
  private readonly source: BrowserDriveSource;
  private readonly scope: DriveRootScope;
  private readonly index: MetadataIndex;
  private readonly enrollment: () => EnrollmentView;
  private readonly fingerprint: () => string;
  private readonly maxDownloadBytes: number;

  constructor(options: BrowserControllerOptions) {
    if (!options.source || typeof options.source.listChildren !== "function") throw new Error("A read-only Drive source is required");
    if (!options.scope) throw new Error("A Drive root scope is required");
    if (!options.index) throw new Error("A metadata index is required");
    this.source = options.source;
    this.scope = options.scope;
    this.index = options.index;
    this.enrollment = options.enrollment;
    this.fingerprint = options.fingerprint ?? (() => "");
    this.maxDownloadBytes = options.maxDownloadBytes ?? BETA_DOWNLOAD_LIMIT_BYTES;
    if (!Number.isFinite(this.maxDownloadBytes) || this.maxDownloadBytes <= 0) throw new Error("The download size cap is invalid");
  }

  get state(): BrowserViewState {
    return describeBrowserState(this.enrollment(), this.fingerprint(), this.scope.rootFolderName);
  }

  private assertEnrolled(): void {
    const state = this.enrollment();
    if (state.status !== "enrolled" || !state.pairId) throw new Error("Not enrolled: authorise this device before browsing Google Drive");
  }

  /** Resolves the configured root and lists it; metadata only. */
  async openRoot(): Promise<IndexedMetadata[]> {
    this.assertEnrolled();
    const rootId = await this.scope.resolveRootId();
    return this.openFolder(rootId);
  }

  /** Lists one in-scope folder. Any id outside the root is refused before I/O. */
  async openFolder(folderId: string): Promise<IndexedMetadata[]> {
    this.assertEnrolled();
    this.scope.assertWithinRoot(folderId);
    const page = await this.source.listChildren(folderId);
    this.scope.registerChildren(folderId, page.files);
    this.index.upsertAll(page.files);
    return page.files.map((file) => ({ ...file }));
  }

  /** Metadata-only search over what has already been listed. Never contacts Drive. */
  search(query: string): IndexedMetadata[] {
    this.assertEnrolled();
    const name = query.trim();
    return name === "" ? this.index.values() : this.index.search({ name });
  }

  /** Indexed metadata for one in-scope file, or null when it was never listed. */
  metadata(fileId: string): IndexedMetadata | null {
    return this.index.get(fileId) ?? null;
  }

  /**
   * Explicit on-demand download of a single in-scope file. The declared size is
   * checked before the bytes are requested and the received length afterwards;
   * there is no bulk or full-vault download path here.
   */
  async download(fileId: string): Promise<{ fileId: string; name: string; mimeType: string; bytes: Uint8Array }> {
    this.assertEnrolled();
    this.scope.assertWithinRoot(fileId);
    const metadata = this.index.get(fileId);
    if (!metadata) throw new Error(`That file is not part of the browsed ${this.scope.rootFolderName} metadata; list its folder first`);
    if (metadata.size > this.maxDownloadBytes) throw new Error(`File exceeds the ${this.maxDownloadBytes} byte beta download limit`);
    const downloaded = await this.source.downloadFile(fileId);
    if (downloaded.bytes.byteLength > this.maxDownloadBytes) throw new Error(`File exceeds the ${this.maxDownloadBytes} byte beta download limit`);
    return downloaded;
  }
}
