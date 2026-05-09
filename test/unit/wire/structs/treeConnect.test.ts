import { describe, it, expect } from "vitest";
import { encodeTreeConnectRequest, decodeTreeConnectResponse } from "../../../../src/wire/structs/treeConnect.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("TREE_CONNECT", () => {
  it("encodes the path as UTF-16LE with proper offset/length", () => {
    const buf = encodeTreeConnectRequest({ path: "\\\\srv\\share" });
    expect(buf.readUInt16LE(0)).toBe(9);
    const off = buf.readUInt16LE(4);
    const len = buf.readUInt16LE(6);
    const got = buf.subarray(off - 64, off - 64 + len).toString("utf16le");
    expect(got).toBe("\\\\srv\\share");
  });

  it("decodes a synthetic response", () => {
    const w = new Writer();
    w.u16(16); // StructureSize
    w.u8(1); // ShareType: DISK
    w.u8(0);
    w.u32(0); // ShareFlags
    w.u32(0); // Capabilities
    w.u32(0x001f01ff); // MaxAccess
    const r = decodeTreeConnectResponse(w.buffer());
    expect(r.shareType).toBe("disk");
  });
});
