import { describe, it, expect } from "vitest";
import {
  encodeQueryInfoRequest,
  decodeQueryInfoResponse,
  decodeFileAllInformation,
  FileInformationClass,
  InfoType,
} from "../../../../src/wire/structs/queryInfo.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("QUERY_INFO", () => {
  it("encodes a FILE info request", () => {
    const fid = Buffer.alloc(16, 0xa1);
    const buf = encodeQueryInfoRequest({
      infoType: InfoType.FILE,
      fileInformationClass: FileInformationClass.FileAllInformation,
      fileId: fid,
      outputBufferLength: 4096,
    });
    expect(buf.readUInt16LE(0)).toBe(41);
    expect(buf.readUInt8(2)).toBe(InfoType.FILE);
    expect(buf.readUInt8(3)).toBe(FileInformationClass.FileAllInformation);
  });

  it("decodes a wrapped output and the FileAllInformation payload", () => {
    // Payload: BasicInformation(40) + StandardInformation(24) + ...
    const inner = new Writer();
    // Basic
    inner.u64(1n); inner.u64(2n); inner.u64(3n); inner.u64(4n); // times
    inner.u32(0x80); // attributes
    inner.u32(0); // reserved
    // Standard
    inner.u64(123n); // alloc
    inner.u64(100n); // EOF
    inner.u32(1); // links
    inner.u8(0); inner.u8(0); inner.u16(0); // delete pending, directory, reserved
    // Internal (8) + EaInformation (4) + AccessInformation (4) + PositionInformation (8) + ModeInformation (4) + AlignmentInformation (4)
    inner.u64(0n); inner.u32(0); inner.u32(0); inner.u64(0n); inner.u32(0); inner.u32(0);
    // NameInformation: u32 length + name (skip)
    inner.u32(0);

    const innerBuf = inner.buffer();
    const w = new Writer();
    w.u16(9); // StructureSize
    w.u16(64 + 8); // OutputBufferOffset
    w.u32(innerBuf.length);
    w.bytes(innerBuf);
    const out = decodeQueryInfoResponse(w.buffer(), 64);
    const fai = decodeFileAllInformation(out);
    expect(fai.endOfFile).toBe(100n);
    expect(fai.fileAttributes).toBe(0x80);
  });
});
