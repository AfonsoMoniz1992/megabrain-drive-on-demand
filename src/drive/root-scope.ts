/**
 * The only Drive root the mobile beta may browse.
 *
 * Google `drive.readonly` is not folder-scoped authorization, so this class is
 * a product filter over a broader grant: it resolves the numeric id of the
 * `example-test-root` folder and rejects every path or id that is not provably a
 * descendant of it. Nothing here writes, moves or deletes.
 */

export const DRIVE_FOLDER_MIME = "application/vnd.google-apps.folder";

/** Single source of truth for the beta root name (also used by the lease). */
export const BETA_ROOT_FOLDER_NAME = "example-test-root";

export interface DriveFolderRef {
  id: string;
  name: string;
  mimeType: string;
}

/** Metadata-only lookup used to bootstrap the root id. */
export interface RootFolderSource {
  listFoldersByName(name: string): Promise<DriveFolderRef[]>;
}

/** Drive ids are opaque base64url-safe tokens; anything else is a path escape. */
const DRIVE_ID_PATTERN = /^[A-Za-z0-9_-]{1,256}$/;

export interface DriveRootScopeOptions {
  rootFolderName?: string;
}

export class DriveRootScope {
  private readonly source: RootFolderSource;
  private readonly name: string;
  private root: string | null = null;
  private readonly parentOf = new Map<string, string>();

  constructor(source: RootFolderSource, rootFolderName: string = BETA_ROOT_FOLDER_NAME) {
    if (!source || typeof source.listFoldersByName !== "function") throw new Error("A metadata-only root folder source is required");
    this.source = source;
    this.name = rootFolderName;
    if (!this.name) throw new Error("A beta root folder name is required");
  }

  get rootFolderName(): string {
    return this.name;
  }

  get rootId(): string | null {
    return this.root;
  }

  /** Resolves and caches the numeric id of the single beta root folder. */
  async resolveRootId(): Promise<string> {
    if (this.root) return this.root;
    const candidates = (await this.source.listFoldersByName(this.name)).filter((folder) => folder.name === this.name && folder.mimeType === DRIVE_FOLDER_MIME);
    if (candidates.length === 0) throw new Error(`The ${this.name} folder was not found in this Drive account`);
    if (candidates.length > 1) throw new Error(`The ${this.name} folder is ambiguous in this Drive account`);
    const id = candidates[0].id;
    if (!DRIVE_ID_PATTERN.test(id)) throw new Error(`The ${this.name} folder id is invalid`);
    this.root = id;
    return id;
  }

  /** Records listed children so later operations can prove they are in scope. */
  registerChildren(parentId: string, children: Array<{ id: string }>): void {
    this.assertWithinRoot(parentId);
    for (const child of children) {
      if (!DRIVE_ID_PATTERN.test(child.id)) throw new Error(`Drive ID is outside the ${this.name} root`);
      this.parentOf.set(child.id, parentId);
    }
  }

  isWithinRoot(fileId: string): boolean {
    if (this.root === null || !DRIVE_ID_PATTERN.test(fileId)) return false;
    if (fileId === this.root) return true;
    const seen = new Set<string>([fileId]);
    let current = this.parentOf.get(fileId);
    while (current !== undefined) {
      if (current === this.root) return true;
      if (seen.has(current)) return false;
      seen.add(current);
      current = this.parentOf.get(current);
    }
    return false;
  }

  assertWithinRoot(fileId: string): string {
    if (!this.isWithinRoot(fileId)) throw new Error(`Drive ID is outside the ${this.name} root: ${describeRejection(fileId)}`);
    return fileId;
  }

  /**
   * Splits a user-entered relative path. Absolute paths, backslashes, empty
   * segments, `.` and `..` are rejected outright rather than normalised, so a
   * crafted path can never silently resolve outside the beta root.
   */
  resolveRelativePath(path: string): string[] {
    if (path === "") return [];
    const trimmed = path.trim();
    const reject = (): never => { throw new Error(`GDrive Streaming directory paths must be relative and must not leave the ${this.name} root`); };
    if (trimmed === "" || trimmed.startsWith("/") || trimmed.startsWith("\\") || trimmed.includes("\\")) reject();
    if (/[\u0000-\u001f]/.test(trimmed)) reject();
    const segments = trimmed.split("/");
    for (const segment of segments) {
      if (segment === "" || segment === "." || segment === "..") reject();
    }
    return segments;
  }
}

/** Never echo the offending value; it may be attacker-controlled input. */
function describeRejection(fileId: string): string {
  if (fileId.includes("/") || fileId.includes("\\")) return "path-like id";
  if (fileId === ".." || fileId === ".") return "path traversal";
  return "unregistered id";
}
