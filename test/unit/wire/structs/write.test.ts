import { describe, it, expect } from "vitest";
import { encodeWriteRequest, decodeWriteResponse } from "../../../../src/wire/structs/write.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("WRITE", () => {
  it("encodes data with proper offset and FileId", () => {
    const fid = Buffer.alloc(16, 0xab);
    const data = Buffer.from("deadbeef", "hex");
    const buf = encodeWriteRequest({ fileId: fid, offset: 4096n, data });
    expect(buf.readUInt16LE(0)).toBe(49);
    const dataOffset = buf.readUInt16LE(2);
    const dataLen = buf.readUInt32LE(4);
    expect(dataLen).toBe(data.length);
    expect(buf.subarray(dataOffset - 64, dataOffset - 64 + dataLen).equals(data)).toBe(true);
    expect(buf.readBigUInt64LE(8)).toBe(4096n);
    expect(buf.subarray(16, 32).equals(fid)).toBe(true);
  });

  it("decodes a synthetic response", () => {
    const w = new Writer();
    w.u16(17);
    w.u16(0);
    w.u32(2048); // Count
    w.u32(0);
    w.u16(0); w.u16(0);
    expect(decodeWriteResponse(w.buffer())).toBe(2048);
  });
});
