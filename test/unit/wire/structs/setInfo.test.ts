import { describe, it, expect } from "vitest";
import {
  encodeSetInfoRequest,
  encodeFileRenameInformation,
} from "../../../../src/wire/structs/setInfo.js";
import { InfoType, FileInformationClass } from "../../../../src/wire/structs/queryInfo.js";

describe("SET_INFO + FileRenameInformation", () => {
  it("encodes the rename info as ReplaceIfExists+Reserved+RootDir+FileNameLength+FileName(UTF-16LE)", () => {
    const ri = encodeFileRenameInformation({ replaceIfExists: true, fileName: "newname.txt" });
    expect(ri[0]).toBe(1);
    expect(ri.readUInt32LE(16)).toBe("newname.txt".length * 2);
    expect(ri.subarray(20).toString("utf16le")).toBe("newname.txt");
  });

  it("encodes SET_INFO request with FileId and inner buffer", () => {
    const fid = Buffer.alloc(16, 0xaa);
    const inner = encodeFileRenameInformation({ replaceIfExists: false, fileName: "x" });
    const buf = encodeSetInfoRequest({
      infoType: InfoType.FILE,
      fileInformationClass: FileInformationClass.FileRenameInformation,
      fileId: fid,
      buffer: inner,
    });
    expect(buf.readUInt16LE(0)).toBe(33);
    expect(buf.readUInt8(2)).toBe(InfoType.FILE);
    expect(buf.readUInt8(3)).toBe(FileInformationClass.FileRenameInformation);
    expect(buf.readUInt32LE(4)).toBe(inner.length);
  });
});
