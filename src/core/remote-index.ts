export interface RemoteFile {
  id: string;
  name: string;
  path: string;
  parentId: string | null;
  mimeType: string;
  modifiedTime: string;
  revision: string;
  size: number;
  trashed: boolean;
}

export class RemoteIndex {
  private readonly byId = new Map<string, RemoteFile>();

  upsert(file: RemoteFile): void { this.byId.set(file.id, { ...file }); }
  get(id: string): RemoteFile | undefined {
    const item = this.byId.get(id);
    return item ? { ...item } : undefined;
  }
  remove(id: string): void { this.byId.delete(id); }
  move(id: string, path: string, parentId: string | null, modifiedTime: string, revision: string): void {
    const existing = this.byId.get(id);
    if (!existing) throw new Error(`Unknown Drive file ${id}`);
    this.byId.set(id, { ...existing, name: path.split("/").at(-1) ?? existing.name, path, parentId, modifiedTime, revision });
  }
  search(query: string): RemoteFile[] {
    const needle = query.trim().toLocaleLowerCase();
    return [...this.byId.values()]
      .filter((item) => !item.trashed && (!needle || item.path.toLocaleLowerCase().includes(needle)))
      .sort((a, b) => a.path.localeCompare(b.path))
      .map((item) => ({ ...item }));
  }
  values(): RemoteFile[] { return this.search(""); }
  serialize(): RemoteFile[] { return [...this.byId.values()]; }
  load(files: RemoteFile[]): void { this.byId.clear(); files.forEach((file) => this.upsert(file)); }
}
