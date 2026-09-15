import { describe, expect, it } from "vitest";
import { MetadataIndex, type IndexedMetadata } from "../src/drive/metadata-index";

function entry(overrides: Partial<IndexedMetadata> & { id: string }): IndexedMetadata {
  return { name: "note.md", parentId: "root", mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: 10, ...overrides };
}

describe("metadata index", () => {
  const files: IndexedMetadata[] = [
    entry({ id: "1", name: "Alpha.md", mimeType: "text/markdown", modifiedTime: "2026-01-05T00:00:00Z", parentId: "folder-a" }),
    entry({ id: "2", name: "beta.pdf", mimeType: "application/pdf", modifiedTime: "2026-02-01T00:00:00Z", parentId: "folder-a" }),
    entry({ id: "3", name: "photo.png", mimeType: "image/png", modifiedTime: "2026-03-01T00:00:00Z", parentId: "root" }),
    entry({ id: "4", name: "notes.txt", mimeType: "text/plain", modifiedTime: "2026-04-01T00:00:00Z", parentId: "folder-b", size: 0 })
  ];

  it("indexes, retrieves and removes metadata without any content", () => {
    const index = new MetadataIndex();
    index.upsertAll(files);
    expect(index.size()).toBe(4);
    expect(index.get("1")?.name).toBe("Alpha.md");
    expect(Object.keys(index.get("1") as object).sort()).toEqual(["id", "mimeType", "modifiedTime", "name", "parentId", "size"]);
    index.remove("1");
    expect(index.size()).toBe(3);
    index.clear();
    expect(index.values()).toEqual([]);
  });

  it("searches by name, mime type, parent and date range", () => {
    const index = new MetadataIndex();
    index.upsertAll(files);

    expect(index.search({ name: "alp" }).map((file) => file.id)).toEqual(["1"]);
    expect(index.search({ name: "TXT" }).map((file) => file.id)).toEqual(["4"]);
    expect(index.search({ mimeType: "text/" }).map((file) => file.id).sort()).toEqual(["1", "4"]);
    expect(index.search({ mimeType: "application/pdf" }).map((file) => file.id)).toEqual(["2"]);
    expect(index.search({ parentId: "folder-a" }).map((file) => file.id).sort()).toEqual(["1", "2"]);
    expect(index.search({ modifiedAfter: "2026-02-15T00:00:00Z" }).map((file) => file.id).sort()).toEqual(["3", "4"]);
    expect(index.search({ modifiedBefore: "2026-02-01T00:00:00Z" }).map((file) => file.id).sort()).toEqual(["1", "2"]);
  });

  it("sorts newest first, honours a limit and lists children of a folder", () => {
    const index = new MetadataIndex();
    index.upsertAll(files);
    expect(index.search({}).map((file) => file.id)).toEqual(["4", "3", "2", "1"]);
    expect(index.search({ limit: 2 }).map((file) => file.id)).toEqual(["4", "3"]);
    expect(index.childrenOf("folder-a").map((file) => file.id).sort()).toEqual(["1", "2"]);
    expect(index.childrenOf("missing")).toEqual([]);
  });

  it("updates an existing entry in place and returns copies", () => {
    const index = new MetadataIndex();
    index.upsert(entry({ id: "1", name: "Alpha.md" }));
    index.upsert(entry({ id: "1", name: "Alpha-renamed.md", modifiedTime: "2026-05-01T00:00:00Z" }));
    expect(index.size()).toBe(1);
    expect(index.get("1")?.name).toBe("Alpha-renamed.md");
    const copy = index.get("1")!;
    copy.name = "mutated-locally";
    expect(index.get("1")?.name).toBe("Alpha-renamed.md");
  });
});
