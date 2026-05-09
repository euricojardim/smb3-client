import { describe, it, expect } from "vitest";
import {
  encodeChangeNotifyRequest,
  parseFileNotifyInformation,
  CompletionFilter,
} from "../../../../src/wire/structs/changeNotify.js";
import { encodeCancelRequest } from "../../../../src/wire/structs/cancel.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("CHANGE_NOTIFY", () => {
  it("encodes structure size 32 with completion filter", () => {
    const fid = Buffer.alloc(16, 0xa0);
    const buf = encodeChangeNotifyRequest({
      fileId: fid,
      flags: 1, // WATCH_TREE
      outputBufferLength: 65536,
      completionFilter: CompletionFilter.FILE_NAME | CompletionFilter.LAST_WRITE,
    });
    expect(buf.readUInt16LE(0)).toBe(32);
    expect(buf.readUInt16LE(2)).toBe(1);
    expect(buf.readUInt32LE(4)).toBe(65536);
    expect(buf.readUInt32LE(24)).toBe(CompletionFilter.FILE_NAME | CompletionFilter.LAST_WRITE);
    expect(buf.subarray(8, 24).equals(fid)).toBe(true);
  });

  it("parses FILE_NOTIFY_INFORMATION list", () => {
    function entry(action: number, name: string, isLast: boolean): Buffer {
      const nameBuf = Buffer.from(name, "utf16le");
      const recSize = 12 + nameBuf.length;
      const padded = (recSize + 3) & ~3;
      const w = new Writer();
      w.u32(isLast ? 0 : padded);
      w.u32(action);
      w.u32(nameBuf.length);
      w.bytes(nameBuf);
      w.pad(padded - recSize);
      return w.buffer();
    }
    const buf = Buffer.concat([entry(1, "a.txt", false), entry(2, "b.txt", true)]);
    const items = parseFileNotifyInformation(buf);
    expect(items).toEqual([
      { action: 1, fileName: "a.txt" },
      { action: 2, fileName: "b.txt" },
    ]);
  });

  it("CANCEL encoder is structure size 4", () => {
    const buf = encodeCancelRequest();
    expect(buf.length).toBe(4);
    expect(buf.readUInt16LE(0)).toBe(4);
  });
});
