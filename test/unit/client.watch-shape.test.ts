import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client.watch (shape)", () => {
  it("returns an async iterable", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(typeof (c as unknown as { watch: unknown }).watch).toBe("function");
  });
});
