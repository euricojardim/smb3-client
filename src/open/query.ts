import type { CreateResponse } from "../wire/structs/create.js";
import { FileAttribute } from "../wire/structs/create.js";
import type { FileStat } from "../types.js";
import { smbTimeToDate } from "../paths.js";

export function metaToStat(meta: CreateResponse): FileStat {
  const a = meta.fileAttributes;
  const isDir = (a & FileAttribute.DIRECTORY) !== 0;
  const eof = meta.endOfFile;
  if (eof > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new RangeError("file size exceeds MAX_SAFE_INTEGER; use statBig()");
  }
  return {
    size: Number(eof),
    isFile: !isDir,
    isDirectory: isDir,
    attributes: a,
    readonly: (a & FileAttribute.READONLY) !== 0,
    hidden: (a & FileAttribute.HIDDEN) !== 0,
    system: (a & FileAttribute.SYSTEM) !== 0,
    archive: (a & FileAttribute.ARCHIVE) !== 0,
    ctime: smbTimeToDate(meta.creationTime),
    atime: smbTimeToDate(meta.lastAccessTime),
    mtime: smbTimeToDate(meta.lastWriteTime),
    changeTime: smbTimeToDate(meta.changeTime),
  };
}
