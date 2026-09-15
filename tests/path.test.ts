import { describe, expect, it } from "vitest";
import { cachePathForRemoteFile, cachePathForRemotePath, isPluginCacheRoot, isSafeRemotePath } from "../src/core/path";

describe("remote path safety", () => {
  it("accepts normal Unicode GDriveStreaming paths", () => {
    expect(isSafeRemotePath("projects/São João/ação.md")).toBe(true);
  });

  it("rejects traversal and absolute paths", () => {
    expect(isSafeRemotePath("../secrets.md")).toBe(false);
    expect(isSafeRemotePath("/etc/passwd")).toBe(false);
  });

  it("maps each Drive ID to an isolated plugin-owned cache namespace", () => {
    expect(isPluginCacheRoot("_gdrive-stream-cache")).toBe(true);
    expect(isPluginCacheRoot("notes")).toBe(false);
    expect(cachePathForRemoteFile("_gdrive-stream-cache", "id-a", "a/b.md")).not.toBe(cachePathForRemoteFile("_gdrive-stream-cache", "id-b", "a/b.md"));
    expect(cachePathForRemoteFile("_gdrive-stream-cache", "id/a", "ação.md")).toContain("id%2Fa");
  });
});
