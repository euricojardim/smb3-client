import { Writer, Reader } from "../buffer.js";

export interface ReadRequest {
  fileId: Buffer; // 16 bytes
  offset: bigint;
  length: number;
  minimumCount?: number;
  channel?: number;
}

export function encodeReadRequest(req: ReadRequest): Buffer {
  if (req.fileId.length !== 16) throw new Error("READ: FileId must be 16 bytes");
  const w = new Writer();
  w.u16(49); // StructureSize
  w.u8(0); // Padding
  w.u8(0); // Flags
  w.u32(req.length >>> 0);
  w.u64(req.offset);
  w.bytes(req.fileId);
  w.u32(req.minimumCount ?? 0);
  w.u32(req.channel ?? 0);
  w.u32(0); // RemainingBytes
  w.u16(0); // ReadChannelInfoOffset
  w.u16(0); // ReadChannelInfoLength
  // Buffer must be at least 1 byte
  w.u8(0);
  return w.buffer();
}

export function decodeReadResponse(body: Buffer, bodyAt = 64): Buffer {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 17) throw new Error(`READ resp StructureSize ${ss} != 17`);
  const dataOffset = r.u8();
  r.u8(); // Reserved
  const dataLength = r.u32();
  r.u32(); // DataRemaining
  r.u32(); // Reserved2 / Flags
  const start = dataOffset - bodyAt;
  return Buffer.from(body.subarray(start, start + dataLength));
}
