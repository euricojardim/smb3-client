import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client.mkdir (shape)", () => {
  it("is a function", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(typeof (c as unknown as { mkdir: unknown }).mkdir).toBe("function");
  });
});
