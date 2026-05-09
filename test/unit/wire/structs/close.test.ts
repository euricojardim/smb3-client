import { describe, it, expect } from "vitest";
import { encodeCloseRequest, decodeCloseResponse } from "../../../../src/wire/structs/close.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("CLOSE", () => {
  it("encodes structure size 24 with FileId", () => {
    const fid = Buffer.alloc(16, 0xab);
    const buf = encodeCloseRequest(fid);
    expect(buf.readUInt16LE(0)).toBe(24);
    expect(buf.subarray(8, 24).equals(fid)).toBe(true);
  });
  it("decodes a synthetic response", () => {
    const w = new Writer();
    w.u16(60); w.u16(0); w.u32(0);
    w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n);
    w.u64(0n); w.u64(0n); w.u32(0);
    expect(() => decodeCloseResponse(w.buffer())).not.toThrow();
  });
});
