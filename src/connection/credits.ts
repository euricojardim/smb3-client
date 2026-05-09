interface Waiter {
  n: number;
  resolve: () => void;
}

export class CreditWindow {
  private waiters: Waiter[] = [];

  constructor(private credits: number) {}

  available(): number {
    return this.credits;
  }

  take(n: number): Promise<void> {
    if (n <= 0) return Promise.resolve();
    if (this.credits >= n) {
      this.credits -= n;
      return Promise.resolve();
    }
    return new Promise<void>((resolve) => {
      this.waiters.push({ n, resolve });
    });
  }

  release(n: number): void {
    if (n <= 0) return;
    this.credits += n;
    while (this.waiters.length > 0 && this.credits >= this.waiters[0]!.n) {
      const w = this.waiters.shift()!;
      this.credits -= w.n;
      w.resolve();
    }
  }
}
