import { describe, it, expect } from "vitest";
import { encodeReadRequest, decodeReadResponse } from "../../../../src/wire/structs/read.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("READ", () => {
  it("encodes offset, length, fileId", () => {
    const fid = Buffer.alloc(16, 0xab);
    const buf = encodeReadRequest({ fileId: fid, offset: 0n, length: 4096 });
    expect(buf.readUInt16LE(0)).toBe(49);
    expect(buf.readUInt32LE(4)).toBe(4096);
    expect(buf.readBigUInt64LE(8)).toBe(0n);
    expect(buf.subarray(16, 32).equals(fid)).toBe(true);
  });

  it("decodes a synthetic response with payload", () => {
    const payload = Buffer.from("deadbeef", "hex");
    const w = new Writer();
    w.u16(17);
    const dataOffset = 64 + 16; // body offset 16 from start (StructureSize=2 + DataOffset=1 + Reserved=1 = 4; rest)
    w.u8(dataOffset);
    w.u8(0);
    w.u32(payload.length); // DataLength
    w.u32(0); // DataRemaining
    w.u32(0); // Reserved2
    w.bytes(payload);
    const got = decodeReadResponse(w.buffer(), 64);
    expect(got).toEqual(payload);
  });
});
