import { Writer, Reader } from "../buffer.js";

export function encodeCloseRequest(fileId: Buffer, requestPostQueryAttribs = false): Buffer {
  if (fileId.length !== 16) throw new Error("CLOSE: FileId must be 16 bytes");
  const w = new Writer();
  w.u16(24);
  w.u16(requestPostQueryAttribs ? 1 : 0);
  w.u32(0); // Reserved
  w.bytes(fileId);
  return w.buffer();
}

export interface CloseResponse {
  flags: number;
}

export function decodeCloseResponse(body: Buffer): CloseResponse {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 60) throw new Error(`CLOSE resp StructureSize ${ss} != 60`);
  const flags = r.u16();
  return { flags };
}
