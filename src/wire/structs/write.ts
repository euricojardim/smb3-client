import { Reader, Writer } from "../buffer.js";

export interface WriteRequest {
  fileId: Buffer; // 16 bytes
  offset: bigint;
  data: Buffer;
  channel?: number;
  flags?: number;
}

export function encodeWriteRequest(req: WriteRequest): Buffer {
  if (req.fileId.length !== 16) throw new Error("WRITE: FileId must be 16 bytes");
  const w = new Writer();
  w.u16(49);
  w.u16(64 + 48); // DataOffset (header start + WRITE struct fixed size 48)
  w.u32(req.data.length);
  w.u64(req.offset);
  w.bytes(req.fileId);
  w.u32(req.channel ?? 0);
  w.u32(0); // RemainingBytes
  w.u16(0); // WriteChannelInfoOffset
  w.u16(0); // WriteChannelInfoLength
  w.u32(req.flags ?? 0);
  w.bytes(req.data.length === 0 ? Buffer.from([0]) : req.data);
  return w.buffer();
}

export function decodeWriteResponse(body: Buffer): number {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 17) throw new Error(`WRITE resp StructureSize ${ss} != 17`);
  r.u16(); // Reserved
  const count = r.u32();
  return count;
}
