/**
 * In-memory metadata index for the mobile beta.
 *
 * Only Drive metadata (id, name, parent, mime type, modified time, size) is
 * indexed. File content is never fetched or held here: the beta browses by
 * metadata and downloads explicitly on demand.
 */

export interface IndexedMetadata {
  id: string;
  name: string;
  parentId: string | null;
  mimeType: string;
  modifiedTime: string;
  size: number;
}

export interface SearchQuery {
  name?: string;
  mimeType?: string;
  modifiedAfter?: string;
  modifiedBefore?: string;
  parentId?: string;
  limit?: number;
}

export const DEFAULT_SEARCH_LIMIT = 200;

function toMillis(value: string | undefined): number | null {
  if (value === undefined) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function clone(file: IndexedMetadata): IndexedMetadata {
  return { ...file };
}

export class MetadataIndex {
  private readonly byId = new Map<string, IndexedMetadata>();

  upsert(file: IndexedMetadata): void {
    if (!file.id) throw new Error("Indexed metadata requires a Drive id");
    this.byId.set(file.id, clone(file));
  }

  upsertAll(files: IndexedMetadata[]): void {
    for (const file of files) this.upsert(file);
  }

  get(id: string): IndexedMetadata | undefined {
    const found = this.byId.get(id);
    return found ? clone(found) : undefined;
  }

  remove(id: string): void {
    this.byId.delete(id);
  }

  clear(): void {
    this.byId.clear();
  }

  size(): number {
    return this.byId.size;
  }

  values(): IndexedMetadata[] {
    return this.search({});
  }

  childrenOf(parentId: string, limit = DEFAULT_SEARCH_LIMIT): IndexedMetadata[] {
    if (!parentId) return [];
    return this.search({ parentId, limit });
  }

  search(query: SearchQuery): IndexedMetadata[] {
    const needle = query.name?.trim().toLocaleLowerCase();
    const mime = query.mimeType?.trim().toLocaleLowerCase();
    const after = toMillis(query.modifiedAfter);
    const before = toMillis(query.modifiedBefore);
    const results: IndexedMetadata[] = [];
    for (const file of this.byId.values()) {
      if (query.parentId !== undefined && file.parentId !== query.parentId) continue;
      if (needle && !file.name.toLocaleLowerCase().includes(needle)) continue;
      if (mime) {
        const fileMime = file.mimeType.toLocaleLowerCase();
        if (mime.endsWith("/") ? !fileMime.startsWith(mime) : fileMime !== mime) continue;
      }
      const modified = toMillis(file.modifiedTime);
      if (after !== null && (modified === null || modified < after)) continue;
      if (before !== null && (modified === null || modified > before)) continue;
      results.push(clone(file));
    }
    results.sort((a, b) => (Date.parse(b.modifiedTime) - Date.parse(a.modifiedTime)) || a.name.localeCompare(b.name));
    const limit = query.limit ?? DEFAULT_SEARCH_LIMIT;
    return Number.isFinite(limit) && limit >= 0 ? results.slice(0, limit) : results;
  }
}
