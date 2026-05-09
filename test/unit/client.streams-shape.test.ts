import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client streams (shape)", () => {
  it("exposes createReadStream and createWriteStream", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(typeof (c as unknown as { createReadStream: unknown }).createReadStream).toBe("function");
    expect(typeof (c as unknown as { createWriteStream: unknown }).createWriteStream).toBe("function");
  });
});
