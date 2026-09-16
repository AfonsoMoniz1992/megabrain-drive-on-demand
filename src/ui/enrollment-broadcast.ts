/**
 * Enrollment state broadcaster.
 *
 * The lease manager emits non-secret enrollment state changes while an
 * enrolment is in flight (pairing created, waiting for Google consent, lease
 * applied, pairing dropped). Surfaces that display that state must re-render on
 * every emission: without this, an operator sitting on the settings screen sees
 * a stale "Not enrolled" for the whole consent window and cannot tell whether
 * anything is happening.
 *
 * Deliberately tiny and dependency-free so the fan-out rules stay unit-testable
 * outside Obsidian: a listener that throws, or that subscribes or unsubscribes
 * during a notification, must never break the enrolment itself.
 */
export class EnrollmentBroadcast {
  private readonly listeners = new Set<() => void>();

  /** Registers a listener and returns its unsubscribe function. */
  subscribe(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  }

  get size(): number {
    return this.listeners.size;
  }

  /**
   * Notifies a snapshot of the current listeners. Listener failures are
   * swallowed on purpose: a view that cannot render must not abort an enrolment
   * that is already waiting on a Google approval.
   */
  notify(): void {
    for (const listener of [...this.listeners]) {
      try {
        listener();
      } catch {
        // A stale or detached view is not an enrolment failure.
      }
    }
  }
}
