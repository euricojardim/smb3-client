import { describe, it, expect } from "vitest";
import { metaToStat } from "../../../src/open/query.js";

describe("metaToStat", () => {
  it("turns a CREATE response into a FileStat", () => {
    const stat = metaToStat({
      oplockLevel: 0,
      createAction: 2,
      creationTime: 0n,
      lastAccessTime: 0n,
      lastWriteTime: 0n,
      changeTime: 0n,
      allocationSize: 0n,
      endOfFile: 1234n,
      fileAttributes: 0x21, // ARCHIVE | READONLY
      fileId: Buffer.alloc(16),
    });
    expect(stat.size).toBe(1234);
    expect(stat.isFile).toBe(true);
    expect(stat.isDirectory).toBe(false);
    expect(stat.readonly).toBe(true);
    expect(stat.archive).toBe(true);
  });

  it("flags directory", () => {
    const stat = metaToStat({
      oplockLevel: 0,
      createAction: 2,
      creationTime: 0n,
      lastAccessTime: 0n,
      lastWriteTime: 0n,
      changeTime: 0n,
      allocationSize: 0n,
      endOfFile: 0n,
      fileAttributes: 0x10, // DIRECTORY
      fileId: Buffer.alloc(16),
    });
    expect(stat.isDirectory).toBe(true);
    expect(stat.isFile).toBe(false);
  });
});
