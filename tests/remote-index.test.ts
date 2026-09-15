import { describe, expect, it } from "vitest";
import { RemoteIndex } from "../src/core/remote-index";

describe("RemoteIndex", () => {
  it("updates a move without downloading file content", () => {
    const index = new RemoteIndex();
    index.upsert({ id: "root", name: "gdriveStreaming", path: "", parentId: null, mimeType: "application/vnd.google-apps.folder", modifiedTime: "1", revision: "1", size: 0, trashed: false });
    index.upsert({ id: "a", name: "a.md", path: "wiki/a.md", parentId: "root", mimeType: "text/markdown", modifiedTime: "1", revision: "1", size: 20, trashed: false });
    index.move("a", "projects/a.md", "root", "2", "2");
    expect(index.get("a")?.path).toBe("projects/a.md");
    expect(index.search("projects").map((f) => f.id)).toEqual(["a"]);
  });
});
