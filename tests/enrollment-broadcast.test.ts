import { describe, expect, it } from "vitest";
import { EnrollmentBroadcast } from "../src/ui/enrollment-broadcast";

describe("enrollment broadcast", () => {
  it("notifies every subscriber and stops after unsubscribe", () => {
    const broadcast = new EnrollmentBroadcast();
    let first = 0;
    let second = 0;
    const unsubscribeFirst = broadcast.subscribe(() => { first += 1; });
    const unsubscribeSecond = broadcast.subscribe(() => { second += 1; });
    expect(broadcast.size).toBe(2);

    broadcast.notify();
    expect([first, second]).toEqual([1, 1]);

    unsubscribeFirst();
    broadcast.notify();
    expect([first, second]).toEqual([1, 2]);
    expect(broadcast.size).toBe(1);
    unsubscribeSecond();
    expect(broadcast.size).toBe(0);
    broadcast.notify();
    expect([first, second]).toEqual([1, 2]);
  });

  /**
   * Regression for the reported symptom: an operator sat on the settings screen
   * during the whole consent window and saw a stale "Not enrolled" because
   * nothing re-rendered. Views must therefore be notified on every emission, and
   * one broken view must not stop the others.
   */
  it("keeps notifying the remaining subscribers when one view throws", () => {
    const broadcast = new EnrollmentBroadcast();
    const seen: string[] = [];
    broadcast.subscribe(() => { seen.push("broken"); throw new Error("detached view"); });
    broadcast.subscribe(() => { seen.push("healthy"); });

    expect(() => broadcast.notify()).not.toThrow();
    expect(seen).toEqual(["broken", "healthy"]);
  });

  it("survives a subscriber that unsubscribes itself while being notified", () => {
    const broadcast = new EnrollmentBroadcast();
    const order: string[] = [];
    const selfRemoving = () => {
      order.push("self-removing");
      unsubscribe();
    };
    const unsubscribe = broadcast.subscribe(selfRemoving);
    broadcast.subscribe(() => { order.push("other"); });

    broadcast.notify();
    broadcast.notify();
    expect(order).toEqual(["self-removing", "other", "other"]);
  });
});
