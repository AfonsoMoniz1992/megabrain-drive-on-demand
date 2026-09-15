import type { IndexedMetadata } from "./metadata-index";
import { DriveRootScope, DRIVE_FOLDER_MIME, type DriveFolderRef } from "./root-scope";

/**
 * Read-only Google Drive client for the mobile beta.
 *
 * Every request is an HTTP GET against the Drive v3 metadata/read endpoints.
 * There is deliberately no create, update, delete, trash, rename, move, copy or
 * upload path in this module, and there never may be one in the beta. Content
 * is fetched only by an explicit `downloadFile` call under an enforced size cap
 * — there is no automatic full-vault synchronisation.
 *
 * The bearer token is supplied by a callback so it never lives in this object
 * and never appears in an error message or a log line.
 */

export const DRIVE_API_BASE = "https://www.googleapis.com/drive/v3";

/** Metadata-only field mask. `alt=media` is never combined with this list. */
export const METADATA_FIELDS = "id,name,mimeType,modifiedTime,size,parents";
export const FOLDER_FIELDS = "id,name,mimeType";

export const DEFAULT_MAX_DOWNLOAD_BYTES = 25 * 1024 * 1024;

export interface DriveReadRequest {
  url: string;
  method: "GET";
  headers: Record<string, string>;
}

export interface DriveReadResponse {
  status: number;
  json?: unknown;
  arrayBuffer?: ArrayBuffer;
}

/** Transport injected by the plugin (`obsidianTransport` in production). */
export interface DriveReadTransport {
  request(request: DriveReadRequest): Promise<DriveReadResponse>;
}

export interface DriveReadClientOptions {
  transport: DriveReadTransport;
  accessToken: () => string;
  scope: DriveRootScope;
  maxDownloadBytes?: number;
}

export interface DriveMetadataPage {
  files: IndexedMetadata[];
  nextPageToken?: string;
}

export interface DownloadedFile {
  fileId: string;
  name: string;
  mimeType: string;
  bytes: Uint8Array;
}

function buildQuery(params: Record<string, string | number | undefined>): string {
  return Object.entries(params)
    .filter((entry): entry is [string, string | number] => entry[1] !== undefined)
    .map(([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`)
    .join("&");
}

/** Neutralise Drive query syntax inside a value; `'` must be backslash-escaped. */
function driveQueryLiteral(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
}

function asRecord(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Google Drive returned an unexpected response");
  return value as Record<string, unknown>;
}

function toIndexedMetadata(value: unknown): IndexedMetadata {
  const record = asRecord(value);
  const parents = record.parents;
  return {
    id: String(record.id ?? ""),
    name: String(record.name ?? ""),
    parentId: Array.isArray(parents) && parents.length > 0 ? String(parents[0]) : null,
    mimeType: String(record.mimeType ?? "application/octet-stream"),
    modifiedTime: String(record.modifiedTime ?? ""),
    size: Number(record.size ?? 0)
  };
}

export class DriveReadClient {
  private readonly transport: DriveReadTransport;
  private readonly accessToken: () => string;
  private readonly scope: DriveRootScope;
  private readonly maxDownloadBytes: number;

  constructor(options: DriveReadClientOptions) {
    if (!options.transport || typeof options.transport.request !== "function") throw new Error("A Drive transport is required");
    this.transport = options.transport;
    this.accessToken = options.accessToken;
    this.scope = options.scope;
    this.maxDownloadBytes = options.maxDownloadBytes ?? DEFAULT_MAX_DOWNLOAD_BYTES;
    if (!Number.isFinite(this.maxDownloadBytes) || this.maxDownloadBytes <= 0) throw new Error("The download size cap is invalid");
  }

  /** Resolves (and caches) the example-test-root root id; metadata only. */
  async resolveRootId(): Promise<string> {
    return this.scope.resolveRootId();
  }

  /** Root-folder lookup used to bootstrap the scope; metadata only. */
  async listFoldersByName(name: string): Promise<DriveFolderRef[]> {
    const body = await this.readJson(`${DRIVE_API_BASE}/files?${buildQuery({
      q: `mimeType='${DRIVE_FOLDER_MIME}' and name='${driveQueryLiteral(name)}' and trashed=false`,
      fields: `files(${FOLDER_FIELDS})`,
      pageSize: 100
    })}`);
    const files = Array.isArray(body.files) ? body.files : [];
    return files.map((file) => {
      const record = asRecord(file);
      return { id: String(record.id ?? ""), name: String(record.name ?? ""), mimeType: String(record.mimeType ?? "") };
    });
  }

  /** Lists the direct children of an in-scope folder; never downloads content. */
  async listChildren(parentId: string, pageToken?: string): Promise<DriveMetadataPage> {
    this.scope.assertWithinRoot(parentId);
    const body = await this.readJson(`${DRIVE_API_BASE}/files?${buildQuery({
      q: `'${driveQueryLiteral(parentId)}' in parents and trashed = false`,
      fields: `nextPageToken,files(${METADATA_FIELDS})`,
      orderBy: "folder,name",
      pageSize: 1000,
      pageToken
    })}`);
    const files = (Array.isArray(body.files) ? body.files : []).map(toIndexedMetadata);
    this.scope.registerChildren(parentId, files);
    return { files, nextPageToken: typeof body.nextPageToken === "string" ? body.nextPageToken : undefined };
  }

  /** Fetches metadata for one in-scope file. */
  async getMetadata(fileId: string): Promise<IndexedMetadata> {
    this.scope.assertWithinRoot(fileId);
    const body = await this.readJson(`${DRIVE_API_BASE}/files/${encodeURIComponent(fileId)}?${buildQuery({ fields: METADATA_FIELDS })}`);
    return toIndexedMetadata(body);
  }

  /**
   * Explicit on-demand content download. The declared size is checked before
   * the bytes are requested and the received length is checked afterwards.
   */
  async downloadFile(fileId: string): Promise<DownloadedFile> {
    this.scope.assertWithinRoot(fileId);
    const metadata = await this.getMetadata(fileId);
    if (metadata.size > this.maxDownloadBytes) throw new Error(`File exceeds the ${this.maxDownloadBytes} byte beta download limit`);
    const response = await this.request(`${DRIVE_API_BASE}/files/${encodeURIComponent(fileId)}?${buildQuery({ alt: "media" })}`);
    if (!response.arrayBuffer) throw new Error(`Google Drive read failed (${response.status})`);
    const bytes = new Uint8Array(response.arrayBuffer);
    if (bytes.byteLength > this.maxDownloadBytes) throw new Error(`File exceeds the ${this.maxDownloadBytes} byte beta download limit`);
    return { fileId, name: metadata.name, mimeType: metadata.mimeType, bytes };
  }

  /** The only place this module issues HTTP: GET, Drive base URL, bearer token. */
  private request(url: string): Promise<DriveReadResponse> {
    if (!url.startsWith(`${DRIVE_API_BASE}/`)) throw new Error("Refusing a Drive request outside the Drive v3 API base");
    const token = this.accessToken();
    if (!token) throw new Error("No active read-only lease");
    return this.transport.request({ url, method: "GET", headers: { Authorization: `Bearer ${token}` } });
  }

  private async readJson(url: string): Promise<Record<string, unknown>> {
    const response = await this.request(url);
    if (response.status < 200 || response.status >= 300) throw new Error(`Google Drive read failed (${response.status})`);
    return asRecord(response.json);
  }
}
