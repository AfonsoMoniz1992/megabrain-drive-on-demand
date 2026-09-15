import { describe, expect, it } from "vitest";
import { LatestWriteQueue } from "../src/settings-write-queue";

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => { resolve = done; });
  return { promise, resolve };
}

describe("LatestWriteQueue", () => {
  it("serializes an in-flight old write before the newest enrollment snapshot", async () => {
    const queue = new LatestWriteQueue();
    const firstWriteMayFinish = deferred();
    const firstWriteStarted = deferred();
    const written: string[] = [];

    const oldWrite = queue.enqueue(async () => {
      written.push("old-start");
      firstWriteStarted.resolve();
      await firstWriteMayFinish.promise;
      written.push("old-finished");
    });
    await firstWriteStarted.promise;

    const enrolledWrite = queue.enqueue(async () => { written.push("enrolled-pair-id"); });
    firstWriteMayFinish.resolve();
    await Promise.all([oldWrite, enrolledWrite]);

    expect(written).toEqual(["old-start", "old-finished", "enrolled-pair-id"]);
  });

  it("drops queued stale snapshots and writes only the most recent state", async () => {
    const queue = new LatestWriteQueue();
    const firstWriteMayFinish = deferred();
    const firstWriteStarted = deferred();
    const written: string[] = [];

    const runningOldWrite = queue.enqueue(async () => {
      written.push("running-old");
      firstWriteStarted.resolve();
      await firstWriteMayFinish.promise;
    });
    await firstWriteStarted.promise;
    const staleWrite = queue.enqueue(async () => { written.push("stale"); });
    const newestEnrollmentWrite = queue.enqueue(async () => { written.push("enrolled-pair-id"); });

    firstWriteMayFinish.resolve();
    await Promise.all([runningOldWrite, staleWrite, newestEnrollmentWrite]);

    expect(written).toEqual(["running-old", "enrolled-pair-id"]);
  });
});
