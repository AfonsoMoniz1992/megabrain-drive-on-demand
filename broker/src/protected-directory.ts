import { chmod, mkdir, stat } from "node:fs/promises";

/**
 * Shared directory guard for encrypted at-rest stores.
 *
 * A store directory must be inaccessible to group and other (0700) and must be
 * owned by the service UID. A pre-existing directory with wider permissions is
 * tightened rather than trusted; a directory owned by another UID is refused
 * outright, because writing secrets under a directory another account controls
 * would let that account read or replace them.
 */

export type ProtectedDirectoryErrorCode = "not_owned" | "insecure" | "io_error";

/** Typed failure. Messages are fixed strings and never carry key material. */
export class ProtectedDirectoryError extends Error {
  readonly code: ProtectedDirectoryErrorCode;

  constructor(code: ProtectedDirectoryErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "ProtectedDirectoryError";
    this.code = code;
  }
}

const DIRECTORY_MODE = 0o700;

function isMissingPath(error: unknown): boolean {
  return typeof error === "object" && error !== null && (error as NodeJS.ErrnoException).code === "ENOENT";
}

function serviceUid(): number {
  return typeof process.getuid === "function" ? process.getuid() : -1;
}

/**
 * Verifies (and, for a wider pre-existing directory, enforces) that `directory`
 * is 0700 and owned by the service UID. With `create` the directory is created
 * 0700 when absent; otherwise a missing directory is treated as "nothing to
 * protect yet" and returns quietly.
 */
export async function ensureProtectedDirectory(directory: string, options?: { create?: boolean }): Promise<void> {
  let stats;
  try {
    stats = await stat(directory);
  } catch (error) {
    if (!isMissingPath(error)) {
      throw new ProtectedDirectoryError("io_error", "Protected directory could not be inspected", { cause: error });
    }
    if (!options?.create) return;
    try {
      await mkdir(directory, { recursive: true, mode: DIRECTORY_MODE });
      stats = await stat(directory);
    } catch (createError) {
      throw new ProtectedDirectoryError("io_error", "Protected directory could not be created", { cause: createError });
    }
  }

  if (!stats.isDirectory()) {
    throw new ProtectedDirectoryError("insecure", "Protected path is not a directory");
  }

  const uid = serviceUid();
  if (uid >= 0 && stats.uid !== uid) {
    throw new ProtectedDirectoryError("not_owned", "Protected directory is not owned by the service uid");
  }

  if ((stats.mode & 0o777) !== DIRECTORY_MODE) {
    try {
      await chmod(directory, DIRECTORY_MODE);
      const verified = await stat(directory);
      if ((verified.mode & 0o777) !== DIRECTORY_MODE) {
        throw new ProtectedDirectoryError("insecure", "Protected directory permissions could not be restricted to 0700");
      }
    } catch (error) {
      if (error instanceof ProtectedDirectoryError) throw error;
      throw new ProtectedDirectoryError("io_error", "Protected directory permissions could not be enforced", { cause: error });
    }
  }
}
