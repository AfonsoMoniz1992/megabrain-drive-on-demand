export interface CacheEntry {
  id: string;
  bytes: number;
  pinned: boolean;
  lastAccessed: number;
}

/** Select non-pinned least-recently-used entries until total cache is in budget. */
export function selectEvictions(entries: CacheEntry[], maxBytes: number): string[] {
  let total = entries.reduce((sum, entry) => sum + entry.bytes, 0);
  if (total <= maxBytes) return [];
  const evictions: string[] = [];
  for (const entry of [...entries].filter((entry) => !entry.pinned).sort((a, b) => a.lastAccessed - b.lastAccessed)) {
    if (total <= maxBytes) break;
    total -= entry.bytes;
    evictions.push(entry.id);
  }
  return evictions;
}
