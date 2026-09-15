export const PLUGIN_CACHE_ROOT = "_gdrive-stream-cache";

export function isSafeRemotePath(remotePath: string): boolean {
  if (!remotePath || remotePath.startsWith("/") || remotePath.includes("\\")) return false;
  return remotePath.split("/").every((part) => part.length > 0 && part !== "." && part !== "..");
}

/** Cache deletion is permitted only inside this fixed plugin-owned namespace. */
export function isPluginCacheRoot(value: string): boolean { return value === PLUGIN_CACHE_ROOT; }

/** Legacy logical cache mapping; do not use it for Drive files because names may collide. */
export function cachePathForRemotePath(cacheRoot: string, remotePath: string): string {
  if (!isPluginCacheRoot(cacheRoot) || !isSafeRemotePath(remotePath)) throw new Error("Unsafe cache path");
  return `${cacheRoot}/${remotePath}`;
}

/** A Drive ID prevents same-name siblings from sharing a local materialization. */
export function cachePathForRemoteFile(cacheRoot: string, driveFileId: string, displayName: string): string {
  if (!isPluginCacheRoot(cacheRoot) || !driveFileId || !displayName) throw new Error("Unsafe cache path");
  return `${cacheRoot}/by-id/${encodeURIComponent(driveFileId)}/${encodeURIComponent(displayName)}`;
}
