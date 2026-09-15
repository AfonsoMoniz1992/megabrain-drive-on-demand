import { describe, expect, it } from "vitest";
import { DRIVE_API_BASE, DriveReadClient, type DriveReadTransport, type DriveReadRequest, type DriveReadResponse } from "../src/drive/drive-read-client";
import { DriveRootScope, type DriveFolderRef } from "../src/drive/root-scope";

const ROOT_ID = "0BxGDriveStreamingDevRoot";
const rootFolder: DriveFolderRef = { id: ROOT_ID, name: "example-test-root", mimeType: "application/vnd.google-apps.folder" };
const rootResponse: DriveReadResponse = { status: 200, json: { files: [rootFolder] } };

interface Harness {
  client: DriveReadClient;
  calls: DriveReadRequest[];
  scope: DriveRootScope;
}

/** Mirrors production wiring: the scope resolves its root through the client. */
function harness(responses: Array<DriveReadResponse | ((request: DriveReadRequest) => DriveReadResponse)>, options: { maxDownloadBytes?: number } = {}): Harness {
  const calls: DriveReadRequest[] = [];
  const queue = [...responses];
  const transport: DriveReadTransport = {
    async request(request) {
      calls.push(request);
      const next = queue.shift() ?? { status: 200, json: { files: [] } };
      return typeof next === "function" ? next(request) : next;
    }
  };
  let client: DriveReadClient;
  const scope = new DriveRootScope({ listFoldersByName: (name: string): Promise<DriveFolderRef[]> => client.listFoldersByName(name) });
  client = new DriveReadClient({ transport, accessToken: () => "ya29.lease-token", scope, maxDownloadBytes: options.maxDownloadBytes });
  return { client, calls, scope };
}

function metadataResponse(overrides: Record<string, unknown> = {}): DriveReadResponse {
  return { status: 200, json: { id: "note-1", name: "Note.md", mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: "12", parents: [ROOT_ID], ...overrides } };
}

function mediaBytes(length: number): ArrayBuffer {
  return new Uint8Array(length).fill(65).buffer;
}

describe("read-only Drive client", () => {
  it("browses the beta root with a metadata-only query", async () => {
    const { client, calls, scope } = harness([
      rootResponse,
      { status: 200, json: { files: [{ id: "note-1", name: "Note.md", mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: "12", parents: [ROOT_ID] }], nextPageToken: "next-page" } }
    ]);

    await expect(client.resolveRootId()).resolves.toBe(ROOT_ID);
    const page = await client.listChildren(ROOT_ID);

    expect(page.nextPageToken).toBe("next-page");
    expect(page.files[0]).toEqual({ id: "note-1", name: "Note.md", parentId: ROOT_ID, mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: 12 });
    const rootQuery = decodeURIComponent(calls[0].url);
    const childQuery = decodeURIComponent(calls[1].url);
    expect(rootQuery).toContain("mimeType='application/vnd.google-apps.folder'");
    expect(rootQuery).toContain("name='example-test-root'");
    expect(rootQuery).toContain("trashed=false");
    expect(rootQuery).toContain("fields=files(id,name,mimeType)");
    expect(childQuery).toContain(`q='${ROOT_ID}' in parents and trashed = false`);
    expect(childQuery).toContain("fields=nextPageToken,files(id,name,mimeType,modifiedTime,size,parents)");
    expect(childQuery).not.toContain("alt=media");
    for (const call of calls) {
      expect(call.method).toBe("GET");
      expect(call.url.startsWith(`${DRIVE_API_BASE}/`)).toBe(true);
      expect(call.url).not.toContain("uploadType");
      expect(call.headers.Authorization).toBe("Bearer ya29.lease-token");
    }
    expect(scope.isWithinRoot("note-1")).toBe(true);
  });

  it("exposes no write, rename, trash or delete capability at any level", () => {
    const forbidden = /upload|create|insert|update|patch|delete|trash|rename|move|copy|write|touch/i;
    const members = [
      ...Object.getOwnPropertyNames(DriveReadClient.prototype),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(DriveReadClient.prototype))
    ];
    expect(members.filter((name) => forbidden.test(name))).toEqual([]);
    expect(members).toContain("downloadFile");
    expect(members).toContain("listChildren");
  });

  it("downloads a file on demand and enforces an explicit size cap", async () => {
    const small = harness([rootResponse, metadataResponse({ size: "4" }), { status: 200, arrayBuffer: mediaBytes(4) }], { maxDownloadBytes: 8 });
    await small.client.resolveRootId();
    small.scope.registerChildren(ROOT_ID, [{ id: "note-1" }]);
    const downloaded = await small.client.downloadFile("note-1");
    expect(downloaded.bytes).toHaveLength(4);
    expect(downloaded.name).toBe("Note.md");
    expect(small.calls).toHaveLength(3);
    expect(decodeURIComponent(small.calls[1].url)).toContain("fields=id,name,mimeType,modifiedTime,size,parents");
    expect(small.calls[1].url).not.toContain("alt=media");
    expect(small.calls[2].url).toContain("alt=media");

    const large = harness([rootResponse, metadataResponse({ id: "big-1", size: "4096" })], { maxDownloadBytes: 8 });
    await large.client.resolveRootId();
    large.scope.registerChildren(ROOT_ID, [{ id: "big-1" }]);
    await expect(large.client.downloadFile("big-1")).rejects.toThrow(/limit/i);
    expect(large.calls).toHaveLength(2);
    expect(large.calls[1].url).not.toContain("alt=media");
  });

  it("rejects a download whose bytes exceed the cap even when metadata lied", async () => {
    const { client, calls, scope } = harness([rootResponse, metadataResponse({ id: "sneaky", size: "1" }), { status: 200, arrayBuffer: mediaBytes(64) }], { maxDownloadBytes: 8 });
    await client.resolveRootId();
    scope.registerChildren(ROOT_ID, [{ id: "sneaky" }]);
    await expect(client.downloadFile("sneaky")).rejects.toThrow(/limit/i);
    expect(calls).toHaveLength(3);
  });

  it("refuses any read outside the resolved root before issuing a request", async () => {
    const { client, calls, scope } = harness([rootResponse]);
    await client.resolveRootId();

    await expect(client.listChildren("foreign-folder-id")).rejects.toThrow(/outside/i);
    await expect(client.getMetadata("../escape")).rejects.toThrow(/outside/i);
    await expect(client.downloadFile("/absolute/path")).rejects.toThrow(/outside/i);
    expect(calls).toHaveLength(1);
    expect(scope.isWithinRoot("foreign-folder-id")).toBe(false);
  });

  it("fails without leaking the Drive error body or the bearer token", async () => {
    const forbidden: (request: DriveReadRequest) => DriveReadResponse = () => ({ status: 403, json: { error: { message: "invalid token ya29.lease-token" } } });
    const { client } = harness([rootResponse, forbidden]);
    await client.resolveRootId();
    try {
      await client.listChildren(ROOT_ID);
      throw new Error("expected failure");
    } catch (error) {
      expect(String(error)).toMatch(/403/);
      expect(String(error)).not.toContain("ya29");
      expect(String(error)).not.toContain("invalid token");
    }
  });
});
