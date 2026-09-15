import { describe, expect, it } from "vitest";
import { publishCacheFile, type AtomicCacheAdapter } from "../src/core/atomic-cache-write";

const destination = "_gdrive-stream-cache/by-id/file-1/note.md";

class MemoryAdapter implements AtomicCacheAdapter {
  readonly files = new Map<string, ArrayBuffer>();
  readonly writes: string[] = [];
  readonly copies: Array<[string, string]> = [];
  readonly removes: string[] = [];
  writeError: Error | null = null;
  copyError: Error | null = null;
  temporarySize: number | null = null;
  /** Simulates a competing writer creating the final file just before copy. */
  createDestinationBeforeCopy: ArrayBuffer | null = null;

  async exists(path: string): Promise<boolean> {
    return this.files.has(path);
  }

  async stat(path: string): Promise<{ size: number } | null> {
    const bytes = this.files.get(path);
    if (!bytes) return null;
    return { size: this.temporarySize ?? bytes.byteLength };
  }

  async writeBinary(path: string, bytes: ArrayBuffer): Promise<void> {
    this.writes.push(path);
    this.files.set(path, bytes.slice(0));
    if (this.writeError) throw this.writeError;
  }

  /** Models DataAdapter.copy's documented fail-if-destination-exists contract. */
  async copy(from: string, to: string): Promise<void> {
    this.copies.push([from, to]);
    if (this.createDestinationBeforeCopy) this.files.set(to, this.createDestinationBeforeCopy.slice(0));
    if (this.copyError) throw this.copyError;
    if (this.files.has(to)) throw new Error("destination exists");
    const bytes = this.files.get(from);
    if (!bytes) throw new Error("missing temporary file");
    this.files.set(to, bytes.slice(0));
  }

  async remove(path: string): Promise<void> {
    this.removes.push(path);
    this.files.delete(path);
  }
}

function bytes(values: number[]): ArrayBuffer {
  return Uint8Array.from(values).buffer;
}

describe("publishCacheFile", () => {
  it("publishes a verified download from a temporary file in the destination directory", async () => {
    const adapter = new MemoryAdapter();

    await publishCacheFile(adapter, destination, bytes([1, 2, 3]));

    expect([...new Uint8Array(adapter.files.get(destination)!)]).toEqual([1, 2, 3]);
    expect(adapter.copies).toHaveLength(1);
    const [temporaryPath, finalPath] = adapter.copies[0];
    expect(finalPath).toBe(destination);
    expect(temporaryPath).toMatch(/^_gdrive-stream-cache\/by-id\/file-1\/\.note\.md\.download-/);
    expect(adapter.files.has(temporaryPath)).toBe(false);
  });

  it("refuses an existing target unchanged, including when a caller retries", async () => {
    const adapter = new MemoryAdapter();
    adapter.files.set(destination, bytes([9]));

    await expect(publishCacheFile(adapter, destination, bytes([1, 2, 3]))).rejects.toThrow(/refusing to replace existing cache file/i);
    await expect(publishCacheFile(adapter, destination, bytes([4, 5, 6]))).rejects.toThrow(/refusing to replace existing cache file/i);

    expect([...new Uint8Array(adapter.files.get(destination)!)]).toEqual([9]);
    expect(adapter.writes).toEqual([]);
    expect(adapter.copies).toEqual([]);
  });

  it("cleans up a temporary file after an interrupted write without creating a final file", async () => {
    const adapter = new MemoryAdapter();
    adapter.writeError = new Error("disk full");

    await expect(publishCacheFile(adapter, destination, bytes([1, 2, 3]))).rejects.toThrow("disk full");

    expect(adapter.files.has(destination)).toBe(false);
    expect(adapter.removes).toEqual(adapter.writes);
    expect(adapter.files.size).toBe(0);
  });

  it("refuses a wrongly sized temporary file and cleans it up", async () => {
    const adapter = new MemoryAdapter();
    adapter.temporarySize = 2;

    await expect(publishCacheFile(adapter, destination, bytes([1, 2, 3]))).rejects.toThrow(/size verification failed/i);

    expect(adapter.files.has(destination)).toBe(false);
    expect(adapter.copies).toEqual([]);
    expect(adapter.removes).toEqual(adapter.writes);
    expect(adapter.files.size).toBe(0);
  });

  it("cleans up after a failed no-clobber copy without creating a final file", async () => {
    const adapter = new MemoryAdapter();
    adapter.copyError = new Error("copy failed");

    await expect(publishCacheFile(adapter, destination, bytes([1, 2, 3]))).rejects.toThrow("copy failed");

    expect(adapter.files.has(destination)).toBe(false);
    expect(adapter.removes).toEqual(adapter.writes);
    expect(adapter.files.size).toBe(0);
  });

  it("does not clobber a destination created in the final check-to-copy race", async () => {
    const adapter = new MemoryAdapter();
    adapter.createDestinationBeforeCopy = bytes([9, 9]);

    await expect(publishCacheFile(adapter, destination, bytes([1, 2, 3]))).rejects.toThrow("destination exists");

    expect([...new Uint8Array(adapter.files.get(destination)!)]).toEqual([9, 9]);
    expect(adapter.copies).toHaveLength(1);
    expect(adapter.files.size).toBe(1);
    expect(adapter.removes).toHaveLength(1);
  });
});
