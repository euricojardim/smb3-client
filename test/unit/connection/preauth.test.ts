import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { PreauthHash } from "../../../src/connection/preauth.js";

describe("PreauthHash", () => {
  it("starts at 64 zero bytes and chains SHA-512(prev || data)", () => {
    const ph = new PreauthHash();
    expect(ph.digest()).toEqual(Buffer.alloc(64));

    const data = Buffer.from("hello", "ascii");
    ph.update(data);
    const expected = createHash("sha512").update(Buffer.concat([Buffer.alloc(64), data])).digest();
    expect(ph.digest()).toEqual(expected);

    const data2 = Buffer.from("world", "ascii");
    ph.update(data2);
    const expected2 = createHash("sha512").update(Buffer.concat([expected, data2])).digest();
    expect(ph.digest()).toEqual(expected2);
  });
});
