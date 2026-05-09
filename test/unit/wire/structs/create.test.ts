import { describe, it, expect } from "vitest";
import { encodeCreateRequest, decodeCreateResponse, CreateOptions, CreateDisposition } from "../../../../src/wire/structs/create.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("CREATE", () => {
  it("encodes filename in UTF-16LE without leading backslash", () => {
    const buf = encodeCreateRequest({
      desiredAccess: 0x00120089,
      shareAccess: 0x00000007,
      createDisposition: CreateDisposition.OPEN,
      createOptions: CreateOptions.NON_DIRECTORY_FILE,
      fileAttributes: 0,
      filename: "dir/file.txt",
    });
    expect(buf.readUInt16LE(0)).toBe(57);
    const nameOff = buf.readUInt16LE(44);
    const nameLen = buf.readUInt16LE(46);
    const got = buf.subarray(nameOff - 64, nameOff - 64 + nameLen).toString("utf16le");
    expect(got).toBe("dir\\file.txt");
  });

  it("decodes a synthetic response", () => {
    const w = new Writer();
    w.u16(89);
    w.u8(0); w.u8(0); // OplockLevel + Flags
    w.u32(2); // CreateAction = OPENED
    w.u64(0n); w.u64(0n); w.u64(0n); w.u64(0n); // 4x FILETIME
    w.u64(123n); // AllocationSize
    w.u64(100n); // EndOfFile
    w.u32(0x80); // FileAttributes
    w.u32(0); // Reserved2
    w.bytes(Buffer.alloc(16, 0xaa)); // FileId
    w.u32(0); w.u32(0); // ContextsOffset/Length
    const r = decodeCreateResponse(w.buffer());
    expect(r.endOfFile).toBe(100n);
    expect(r.fileAttributes).toBe(0x80);
    expect(r.fileId.length).toBe(16);
    expect(r.createAction).toBe(2);
  });
});
