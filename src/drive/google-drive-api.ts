import type { RemoteFile } from "../core/remote-index";

const DRIVE = "https://www.googleapis.com/drive/v3";
const FILE_FIELDS = "id,name,mimeType,modifiedTime,headRevisionId,size,parents,trashed";

export interface HttpRequest { url: string; method?: string; headers?: Record<string, string>; body?: string | ArrayBuffer; }
export interface HttpResponse { status: number; json?: unknown; arrayBuffer?: ArrayBuffer; headers?: Record<string, string>; }
export interface HttpTransport { request(request: HttpRequest): Promise<HttpResponse>; }
export interface DrivePage { files: RemoteFile[]; nextPageToken?: string; }
export interface ChangePage { changes: Array<{ fileId: string; removed?: boolean; file?: RemoteFile }>; nextPageToken?: string; newStartPageToken?: string; }

function encodeParams(input: Record<string, string | undefined>): string {
  return new URLSearchParams(Object.entries(input).filter((entry): entry is [string, string] => entry[1] !== undefined)).toString();
}

export class GoogleDriveApi {
  constructor(private readonly transport: HttpTransport, private readonly accessToken: () => string) {}

  private async get(url: string): Promise<HttpResponse> {
    const response = await this.transport.request({ url, headers: { Authorization: `Bearer ${this.accessToken()}` } });
    if (response.status < 200 || response.status >= 300) throw new Error(`Google Drive GET failed (${response.status})`);
    return response;
  }

  async listChildren(parentId: string, pageToken?: string): Promise<DrivePage> {
    const q = `'${parentId.replace(/'/g, "\\'")}' in parents and trashed = false`;
    const response = await this.get(`${DRIVE}/files?${encodeParams({ q, pageToken, pageSize: "1000", fields: `nextPageToken,files(${FILE_FIELDS})`, orderBy: "folder,name" })}`);
    const body = response.json as { files?: Array<Record<string, unknown>>; nextPageToken?: string };
    return { files: (body.files ?? []).map(toRemoteFile), nextPageToken: body.nextPageToken };
  }

  async getStartPageToken(): Promise<string> {
    const response = await this.get(`${DRIVE}/changes/startPageToken?fields=startPageToken`);
    const body = response.json as { startPageToken?: string };
    if (!body.startPageToken) throw new Error("Google Drive did not return a start page token");
    return body.startPageToken;
  }

  async listChanges(pageToken: string): Promise<ChangePage> {
    const response = await this.get(`${DRIVE}/changes?${encodeParams({ pageToken, pageSize: "1000", fields: `nextPageToken,newStartPageToken,changes(fileId,removed,file(${FILE_FIELDS}))` })}`);
    const body = response.json as { changes?: Array<{ fileId: string; removed?: boolean; file?: Record<string, unknown> }>; nextPageToken?: string; newStartPageToken?: string };
    return { changes: (body.changes ?? []).map((change) => ({ ...change, file: change.file ? toRemoteFile(change.file) : undefined })), nextPageToken: body.nextPageToken, newStartPageToken: body.newStartPageToken };
  }

  async download(fileId: string): Promise<ArrayBuffer> {
    const response = await this.get(`${DRIVE}/files/${encodeURIComponent(fileId)}?alt=media`);
    if (!response.arrayBuffer) throw new Error("Google Drive did not return file bytes");
    return response.arrayBuffer;
  }
}

function toRemoteFile(value: Record<string, unknown>): RemoteFile {
  return {
    id: String(value.id ?? ""), name: String(value.name ?? ""), path: String(value.name ?? ""), parentId: Array.isArray(value.parents) ? String(value.parents[0] ?? "") : null,
    mimeType: String(value.mimeType ?? "application/octet-stream"), modifiedTime: String(value.modifiedTime ?? ""), revision: String(value.headRevisionId ?? ""),
    size: Number(value.size ?? 0), trashed: Boolean(value.trashed)
  };
}
