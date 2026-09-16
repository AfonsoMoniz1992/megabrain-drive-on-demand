import { describe, expect, it } from "vitest";
import { DriveRootScope, type DriveFolderRef, type RootFolderSource } from "../src/drive/root-scope";

const ROOT_ID = "0BxGDriveStreamingDevRoot";

function sourceReturning(folders: DriveFolderRef[]): RootFolderSource & { names: string[] } {
  const names: string[] = [];
  return {
    names,
    async listFoldersByName(name: string) {
      names.push(name);
      return folders;
    }
  };
}

const rootFolder: DriveFolderRef = { id: ROOT_ID, name: "example-test-root", mimeType: "application/vnd.google-apps.folder" };

describe("drive root scope", () => {
  it("resolves the example-test-root folder id once and caches it", async () => {
    const source = sourceReturning([rootFolder]);
    const scope = new DriveRootScope(source);
    await expect(scope.resolveRootId()).resolves.toBe(ROOT_ID);
    await expect(scope.resolveRootId()).resolves.toBe(ROOT_ID);
    expect(source.names).toEqual(["example-test-root"]);
    expect(scope.rootId).toBe(ROOT_ID);
    expect(scope.rootFolderName).toBe("example-test-root");
  });

  it("refuses a missing or ambiguous beta root", async () => {
    await expect(new DriveRootScope(sourceReturning([])).resolveRootId()).rejects.toThrow(/not found/i);
    await expect(new DriveRootScope(sourceReturning([rootFolder, { id: "other", name: "example-test-root", mimeType: "application/vnd.google-apps.folder" }])).resolveRootId()).rejects.toThrow(/ambiguous/i);
    await expect(new DriveRootScope(sourceReturning([{ id: "doc", name: "example-test-root", mimeType: "text/markdown" }])).resolveRootId()).rejects.toThrow(/not found/i);
  });

  it("rejects escaping, absolute and malformed user paths", async () => {
    const scope = new DriveRootScope(sourceReturning([rootFolder]));
    expect(scope.resolveRelativePath("")).toEqual([]);
    expect(scope.resolveRelativePath("notes/2026/plan.md")).toEqual(["notes", "2026", "plan.md"]);
    for (const bad of ["/etc/passwd", "../secrets.md", "notes/../../secrets.md", "notes/./plan.md", "notes//plan.md", "notes\\plan.md", "..", ".", "  ", "notes/\u0000bad.md"]) {
      expect(() => scope.resolveRelativePath(bad)).toThrow(/GDrive Streaming directory/i);
    }
  });

  it("accepts only ids registered below the resolved root", async () => {
    const scope = new DriveRootScope(sourceReturning([rootFolder]));
    await scope.resolveRootId();
    scope.registerChildren(ROOT_ID, [{ id: "child-folder" }, { id: "child-note" }]);
    scope.registerChildren("child-folder", [{ id: "grandchild" }]);

    expect(scope.assertWithinRoot(ROOT_ID)).toBe(ROOT_ID);
    expect(scope.assertWithinRoot("child-note")).toBe("child-note");
    expect(scope.assertWithinRoot("grandchild")).toBe("grandchild");
    expect(scope.isWithinRoot("grandchild")).toBe(true);

    expect(() => scope.assertWithinRoot("foreign-file-id")).toThrow(/outside/i);
    expect(() => scope.assertWithinRoot("../escape")).toThrow(/outside/i);
    expect(() => scope.assertWithinRoot("/absolute")).toThrow(/outside/i);
    expect(() => scope.assertWithinRoot("a/b")).toThrow(/outside/i);
    expect(() => scope.registerChildren("foreign-parent", [{ id: "x" }])).toThrow(/outside/i);
  });

  it("cannot be used before the root is resolved", () => {
    const scope = new DriveRootScope(sourceReturning([rootFolder]));
    expect(scope.isWithinRoot(ROOT_ID)).toBe(false);
    expect(() => scope.assertWithinRoot(ROOT_ID)).toThrow(/outside|resolve/i);
  });
});
