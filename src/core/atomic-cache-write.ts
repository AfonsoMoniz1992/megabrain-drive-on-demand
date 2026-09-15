export interface AtomicCacheAdapter {
  exists(path: string): Promise<boolean>;
  stat(path: string): Promise<{ size: number } | null>;
  writeBinary(path: string, bytes: ArrayBuffer): Promise<void>;
  /** Obsidian guarantees this fails when `to` already exists (no-clobber). */
  copy(from: string, to: string): Promise<void>;
  remove(path: string): Promise<void>;
}

let temporarySequence = 0;

function cacheDirectory(finalPath: string): string {
  const separator = finalPath.lastIndexOf("/");
  if (separator <= 0 || separator === finalPath.length - 1) {
    throw new Error(`Cache destination must include a file name: ${finalPath}`);
  }
  return finalPath.slice(0, separator);
}

function cacheFileName(finalPath: string): string {
  return finalPath.slice(finalPath.lastIndexOf("/") + 1);
}

async function uniqueTemporaryPath(adapter: AtomicCacheAdapter, finalPath: string): Promise<string> {
  const directory = cacheDirectory(finalPath);
  const fileName = cacheFileName(finalPath);
  let temporaryPath: string;
  do {
    temporarySequence += 1;
    temporaryPath = `${directory}/.${fileName}.download-${Date.now().toString(36)}-${temporarySequence.toString(36)}.tmp`;
  } while (await adapter.exists(temporaryPath));
  return temporaryPath;
}

/**
 * Publish downloaded bytes only after they are fully written and size-verified.
 * `DataAdapter.copy` has no-clobber semantics, unlike a filesystem rename which
 * may replace a destination created in the check-to-use interval. The temp
 * source remains until the no-clobber copy succeeds, then is removed.
 */
export async function publishCacheFile(adapter: AtomicCacheAdapter, finalPath: string, bytes: ArrayBuffer): Promise<void> {
  if (await adapter.exists(finalPath)) {
    throw new Error(`Refusing to replace existing cache file: ${finalPath}`);
  }

  const temporaryPath = await uniqueTemporaryPath(adapter, finalPath);
  try {
    await adapter.writeBinary(temporaryPath, bytes);
    const temporaryStat = await adapter.stat(temporaryPath);
    if (!temporaryStat || temporaryStat.size !== bytes.byteLength) {
      throw new Error(`Cache size verification failed for ${finalPath}: expected ${bytes.byteLength} bytes, found ${temporaryStat?.size ?? "no temporary file"}`);
    }
    if (await adapter.exists(finalPath)) {
      throw new Error(`Refusing to replace existing cache file: ${finalPath}`);
    }
    // Do not use rename here: the adapter contract for copy explicitly refuses
    // an existing destination, closing the final-path TOCTOU overwrite race.
    await adapter.copy(temporaryPath, finalPath);
    const finalStat = await adapter.stat(finalPath);
    if (!finalStat || finalStat.size !== bytes.byteLength) {
      throw new Error(`Cache final size verification failed for ${finalPath}`);
    }
    await adapter.remove(temporaryPath);
  } catch (error) {
    try {
      await adapter.remove(temporaryPath);
    } catch {
      // Best-effort cleanup must not conceal the download failure.
    }
    throw error;
  }
}
