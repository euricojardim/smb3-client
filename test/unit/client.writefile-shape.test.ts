import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client.writeFile (shape)", () => {
  it("is a function", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(typeof (c as unknown as { writeFile: unknown }).writeFile).toBe("function");
  });
});
