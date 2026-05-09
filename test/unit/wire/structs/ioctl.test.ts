import { describe, it, expect } from "vitest";
import { encodeIoctlRequest, decodeIoctlResponse } from "../../../../src/wire/structs/ioctl.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("IOCTL", () => {
  it("encodes file-handle IOCTL with input buffer", () => {
    const fid = Buffer.alloc(16, 0xa0);
    const input = Buffer.from("aabbccdd", "hex");
    const buf = encodeIoctlRequest({
      ctlCode: 0x0011c017, // FSCTL_PIPE_TRANSCEIVE
      fileId: fid,
      input,
      maxOutputResponse: 1024,
      flags: 1, // SMB2_0_IOCTL_IS_FSCTL
    });
    expect(buf.readUInt16LE(0)).toBe(57);
    expect(buf.readUInt32LE(4)).toBe(0x0011c017);
    expect(buf.readUInt32LE(28)).toBe(input.length);
    expect(buf.subarray(56, 56 + input.length).equals(input)).toBe(true);
  });

  it("decodes IOCTL response output", () => {
    const out = Buffer.from("ee", "hex");
    const w = new Writer();
    w.u16(49);
    w.u16(0); // Reserved
    w.u32(0); // CtlCode
    w.bytes(Buffer.alloc(16)); // FileId
    w.u32(0); w.u32(0); // Input offset/count
    const outOff = 64 + 48 + 1; // body start (64) + struct fixed minus 1; arbitrary value
    w.u32(outOff);
    w.u32(out.length);
    w.u32(0); w.u32(0); // Flags + Reserved2
    // pad to outOff - 64 - current
    const cur = (w as unknown as { offset: number }).offset;
    w.pad(outOff - 64 - cur);
    w.bytes(out);
    const r = decodeIoctlResponse(w.buffer(), 64);
    expect(r).toEqual(out);
  });
});
