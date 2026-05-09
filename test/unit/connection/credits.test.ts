import { describe, it, expect } from "vitest";
import { CreditWindow } from "../../../src/connection/credits.js";

describe("CreditWindow", () => {
  it("take resolves immediately when enough credits", async () => {
    const w = new CreditWindow(5);
    await w.take(3);
    expect(w.available()).toBe(2);
  });

  it("take blocks until release brings enough", async () => {
    const w = new CreditWindow(2);
    await w.take(2);
    let resolved = false;
    const p = w.take(1).then(() => { resolved = true; });
    await new Promise((r) => setImmediate(r));
    expect(resolved).toBe(false);
    w.release(3);
    await p;
    expect(resolved).toBe(true);
    expect(w.available()).toBe(2);
  });

  it("FIFO ordering of waiters", async () => {
    const w = new CreditWindow(0);
    const order: number[] = [];
    const p1 = w.take(1).then(() => order.push(1));
    const p2 = w.take(1).then(() => order.push(2));
    w.release(2);
    await Promise.all([p1, p2]);
    expect(order).toEqual([1, 2]);
  });
});
