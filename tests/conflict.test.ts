import { describe, expect, it } from "vitest";
import { decideWrite } from "../src/core/conflict";

describe("decideWrite", () => {
  it("queues an upload only when the cached edit is based on the current remote revision", () => {
    expect(decideWrite({ localChanged: true, baseRevision: "10", remoteRevision: "10" })).toBe("upload");
  });

  it("creates a conflict rather than silently overwriting an externally changed file", () => {
    expect(decideWrite({ localChanged: true, baseRevision: "10", remoteRevision: "11" })).toBe("conflict");
  });

  it("refreshes unchanged cache when the remote has changed", () => {
    expect(decideWrite({ localChanged: false, baseRevision: "10", remoteRevision: "11" })).toBe("refresh");
  });
});
