import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client.rm/rmdir (shape)", () => {
  it("are functions", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(typeof (c as unknown as { rm: unknown }).rm).toBe("function");
    expect(typeof (c as unknown as { rmdir: unknown }).rmdir).toBe("function");
  });
});
