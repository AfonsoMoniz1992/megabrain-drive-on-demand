import { describe, expect, it } from "vitest";
import { GoogleDriveApi, type HttpTransport } from "../src/drive/google-drive-api";

describe("GoogleDriveApi metadata sync", () => {
  it("lists only metadata fields for a selected folder and never downloads file content", async () => {
    const calls: string[] = [];
    const transport: HttpTransport = {
      async request(request) {
        calls.push(request.url);
        return { status: 200, json: { files: [{ id: "a", name: "a.md", mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", headRevisionId: "1", size: "4", parents: ["root"] }], nextPageToken: undefined } };
      }
    };
    const api = new GoogleDriveApi(transport, () => "token");
    const page = await api.listChildren("root");
    expect(page.files[0].id).toBe("a");
    expect(calls).toHaveLength(1);
    expect(calls[0]).toContain("fields=nextPageToken%2Cfiles");
    expect(calls[0]).not.toContain("alt=media");
  });

  it("uses the Changes feed page token for incremental updates", async () => {
    const seen: string[] = [];
    const api = new GoogleDriveApi({ async request(request) { seen.push(request.url); return { status: 200, json: { changes: [], newStartPageToken: "next" } }; } }, () => "token");
    const page = await api.listChanges("old-token");
    expect(page.newStartPageToken).toBe("next");
    expect(seen[0]).toContain("pageToken=old-token");
  });
});
