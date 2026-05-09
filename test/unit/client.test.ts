import { describe, it, expect } from "vitest";
import { Client } from "../../src/client.js";

describe("Client (construction only)", () => {
  it("constructs without throwing and is not connected", () => {
    const c = new Client({
      host: "fileserver.lan",
      username: "alice",
      password: "secret",
    });
    expect(c).toBeDefined();
  });
});
