/**
 * Serializes plugin-data writes while making queued stale snapshots disposable.
 *
 * Mobile settings fields fire asynchronous changes independently. Without this
 * queue, an older write that started while the operator typed a broker setting
 * can finish after a completed enrollment and erase the persisted pair id.
 * A write already in progress must finish, but queued intermediate snapshots
 * are skipped and the newest snapshot is always the final write.
 */
export class LatestWriteQueue {
  private tail: Promise<void> = Promise.resolve();
  private latestRevision = 0;

  enqueue(write: () => Promise<void>): Promise<void> {
    const revision = ++this.latestRevision;
    const next = this.tail
      .catch(() => undefined)
      .then(async () => {
        if (revision !== this.latestRevision) return;
        await write();
      });
    this.tail = next;
    return next;
  }
}
