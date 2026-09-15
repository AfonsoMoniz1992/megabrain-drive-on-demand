import { describe, expect, it } from "vitest";
import { selectEvictions, type CacheEntry } from "../src/core/cache-policy";

describe("selectEvictions", () => {
  it("never evicts pinned entries and evicts least recently used cached entries first", () => {
    const entries: CacheEntry[] = [
      { id: "pinned", bytes: 80, pinned: true, lastAccessed: 1 },
      { id: "old", bytes: 70, pinned: false, lastAccessed: 2 },
      { id: "new", bytes: 60, pinned: false, lastAccessed: 3 }
    ];
    expect(selectEvictions(entries, 140)).toEqual(["old"]);
  });

  it("does not evict when cache is within limit", () => {
    expect(selectEvictions([{ id: "a", bytes: 10, pinned: false, lastAccessed: 1 }], 10)).toEqual([]);
  });
});
