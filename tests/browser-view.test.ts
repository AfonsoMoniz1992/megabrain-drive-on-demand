import { describe, expect, it } from "vitest";
import { MetadataIndex, type IndexedMetadata } from "../src/drive/metadata-index";
import { DriveRootScope, DRIVE_FOLDER_MIME } from "../src/drive/root-scope";
import type { EnrollmentView } from "../src/auth/lease-manager";
import * as browserState from "../src/ui/browser-state";
import {
  BETA_DOWNLOAD_LIMIT_BYTES,
  BrowserController,
  describeBrowserState,
  type BrowserDriveSource
} from "../src/ui/browser-state";

const ROOT_ID = "0BxGDriveStreamingDevRoot";
const NOTE_ID = "note-1";
const BIG_ID = "big-1";
const FINGERPRINT = "9f2c4b6a1d8e0f3a5c7b9d1e2f4a6c8b0d2e4f6a8c1b3d5e7f9a0c2e4b6d8f1a";

const notEnrolledState: EnrollmentView = { pairId: null, status: "not_enrolled", expiresAtMs: null };
const enrolledState: EnrollmentView = { pairId: "b".repeat(64), status: "enrolled", expiresAtMs: 9_999_999 };
const awaitingConsentState: EnrollmentView = { pairId: "b".repeat(64), status: "awaiting_consent", expiresAtMs: 1_060_000 };

interface FakeDrive extends BrowserDriveSource {
  calls: string[];
}

function fakeDrive(overrides: { bigSize?: number } = {}): FakeDrive {
  const calls: string[] = [];
  return {
    calls,
    async listChildren(parentId: string) {
      calls.push(`listChildren:${parentId}`);
      const files: IndexedMetadata[] = [
        { id: NOTE_ID, name: "Note.md", parentId, mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: 12 },
        { id: "sub-1", name: "Sub", parentId, mimeType: DRIVE_FOLDER_MIME, modifiedTime: "2026-01-02T00:00:00Z", size: 0 },
        { id: BIG_ID, name: "Huge.bin", parentId, mimeType: "application/octet-stream", modifiedTime: "2026-01-03T00:00:00Z", size: overrides.bigSize ?? 4096 }
      ];
      return { files };
    },
    async downloadFile(fileId: string) {
      calls.push(`downloadFile:${fileId}`);
      return { fileId, name: "Note.md", mimeType: "text/markdown", bytes: new Uint8Array(4).fill(65) };
    }
  };
}

function build(options: { enrollment: EnrollmentView; maxDownloadBytes?: number; bigSize?: number; rootName?: string } ) {
  const rootName = options.rootName ?? "example-test-root";
  const drive = fakeDrive({ bigSize: options.bigSize });
  const scope = new DriveRootScope({
    listFoldersByName: async () => [{ id: ROOT_ID, name: rootName, mimeType: DRIVE_FOLDER_MIME }]
  }, rootName);
  const controller = new BrowserController({
    source: drive,
    scope,
    index: new MetadataIndex(),
    enrollment: () => options.enrollment,
    maxDownloadBytes: options.maxDownloadBytes
  });
  return { controller, drive, scope };
}

describe("read-only browser state", () => {
  it("shows an explicit not-enrolled state with an enroll action and blocks every Drive call", async () => {
    const view = describeBrowserState(notEnrolledState, FINGERPRINT, "operator-test-root");
    expect(view.status).toBe("not_enrolled");
    expect(view.canBrowse).toBe(false);
    expect(view.canEnroll).toBe(true);
    expect(view.fingerprint).toBe(FINGERPRINT);
    expect(view.reason).toMatch(/not enrolled/i);

    const { controller, drive } = build({ enrollment: notEnrolledState });
    await expect(controller.openRoot()).rejects.toThrow(/not enrolled/i);
    expect(() => controller.search("note")).toThrow(/not enrolled/i);
    await expect(controller.download(NOTE_ID)).rejects.toThrow(/not enrolled/i);
    expect(drive.calls).toEqual([]);
  });

  it("enables browsing only once enrolled and displays the device fingerprint", () => {
    const view = describeBrowserState(enrolledState, FINGERPRINT, "example-test-root");
    expect(view.status).toBe("enrolled");
    expect(view.canBrowse).toBe(true);
    expect(view.canEnroll).toBe(false);
    expect(view.fingerprint).toBe(FINGERPRINT);
    expect(view.pairId).toBe(enrolledState.pairId);
  });

  it("reports a pairing that still awaits consent as such, never as enrolled", async () => {
    const view = describeBrowserState(awaitingConsentState, FINGERPRINT, "example-test-root");
    expect(view.status).toBe("awaiting_consent");
    expect(view.canBrowse).toBe(false);
    // A second enrollment code must not be offered while the first pairing is
    // still waiting: consuming it would waste the operator's one-time code.
    expect(view.canEnroll).toBe(false);
    expect(view.reason).toMatch(/consent/i);
    expect(browserState.describeEnrollmentLabel(view.status)).toBe("Waiting for Google consent");
    expect(browserState.describeEnrollmentLabel("enrolled")).toBe("Enrolled");
    expect(browserState.describeEnrollmentLabel("not_enrolled")).toBe("Not enrolled");

    const { controller, drive } = build({ enrollment: awaitingConsentState });
    await expect(controller.openRoot()).rejects.toThrow(/not enrolled/i);
    expect(drive.calls).toEqual([]);
  });

  it("names the operator-configured root in diagnostics and scope errors, never a hard-coded default", async () => {
    const rootName = "operator-test-root";
    // Diagnostics must report the folder actually in use.
    expect(describeBrowserState(enrolledState, FINGERPRINT, rootName).reason).toContain(rootName);
    expect(describeBrowserState(enrolledState, FINGERPRINT, rootName).reason).not.toContain("example-test-root");

    const { controller, scope } = build({ enrollment: enrolledState, rootName });
    expect(scope.rootFolderName).toBe(rootName);
    expect(controller.state.reason).toContain(rootName);
    await expect(controller.openRoot()).resolves.toBeDefined();
    expect(() => scope.assertWithinRoot("unregistered-id")).toThrow(new RegExp(rootName));
    expect(() => scope.resolveRelativePath("../escape")).toThrow(new RegExp(rootName));
  });

  it("lists the example-test-root root as metadata only, without any content fetch", async () => {
    const { controller, drive } = build({ enrollment: enrolledState });
    const files = await controller.openRoot();

    expect(files.map((file) => file.name)).toEqual(["Note.md", "Sub", "Huge.bin"]);
    expect(files[0]).toEqual({ id: NOTE_ID, name: "Note.md", parentId: ROOT_ID, mimeType: "text/markdown", modifiedTime: "2026-01-01T00:00:00Z", size: 12 });
    for (const file of files) {
      expect(Object.keys(file).sort()).toEqual(["id", "mimeType", "modifiedTime", "name", "parentId", "size"]);
    }
    expect(drive.calls).toEqual([`listChildren:${ROOT_ID}`]);
  });

  it("refuses to open or download anything outside the example-test-root root", async () => {
    const { controller, drive } = build({ enrollment: enrolledState });
    await controller.openRoot();
    const afterRoot = [...drive.calls];

    await expect(controller.openFolder("foreign-folder-id")).rejects.toThrow(/outside/i);
    await expect(controller.openFolder("../../etc")).rejects.toThrow(/outside/i);
    await expect(controller.download("unregistered-id")).rejects.toThrow(/outside/i);
    expect(drive.calls).toEqual(afterRoot);
  });

  it("searches cached metadata only and never triggers a download or a second listing", async () => {
    const { controller, drive } = build({ enrollment: enrolledState });
    await controller.openRoot();
    const afterRoot = [...drive.calls];

    const results = controller.search("note");
    expect(results).toHaveLength(1);
    expect(Object.keys(results[0]).sort()).toEqual(["id", "mimeType", "modifiedTime", "name", "parentId", "size"]);
    expect(JSON.stringify(results)).not.toContain("bytes");
    expect(drive.calls).toEqual(afterRoot);
  });

  it("downloads a single file on demand under an enforced size cap", async () => {
    const { controller, drive } = build({ enrollment: enrolledState, maxDownloadBytes: 128 });
    await controller.openRoot();

    const downloaded = await controller.download(NOTE_ID);
    expect(downloaded.name).toBe("Note.md");
    expect(downloaded.bytes).toHaveLength(4);
    expect(drive.calls.filter((call) => call.startsWith("downloadFile:"))).toEqual([`downloadFile:${NOTE_ID}`]);
    expect(drive.calls.filter((call) => call.startsWith("listChildren:"))).toHaveLength(1);

    await expect(controller.download(BIG_ID)).rejects.toThrow(/limit/i);
    expect(drive.calls.filter((call) => call.startsWith("downloadFile:"))).toEqual([`downloadFile:${NOTE_ID}`]);
  });

  it("defaults the download cap to the shared beta limit", () => {
    expect(BETA_DOWNLOAD_LIMIT_BYTES).toBe(25 * 1024 * 1024);
  });

  it("exposes no create, rename, move, delete, trash or upload affordance", () => {
    const forbidden = /upload|create|insert|update|patch|delete|trash|rename|move|copy|write|touch/i;
    const members = [
      ...Object.getOwnPropertyNames(BrowserController.prototype),
      ...Object.keys(browserState)
    ];
    expect(members.filter((name) => forbidden.test(name))).toEqual([]);
    expect(members).toContain("download");
    expect(members).toContain("openFolder");
  });
});
