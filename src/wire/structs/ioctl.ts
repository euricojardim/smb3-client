import { Reader, Writer } from "../buffer.js";

export interface IoctlRequest {
  ctlCode: number;
  fileId: Buffer; // 16 bytes
  input: Buffer;
  maxInputResponse?: number;
  maxOutputResponse: number;
  flags: number; // SMB2_0_IOCTL_IS_FSCTL = 0x00000001
}

export function encodeIoctlRequest(req: IoctlRequest): Buffer {
  if (req.fileId.length !== 16) throw new Error("IOCTL: FileId must be 16 bytes");
  const w = new Writer();
  w.u16(57);
  w.u16(0); // Reserved
  w.u32(req.ctlCode);
  w.bytes(req.fileId);
  // Header fixed size 56, so InputOffset = 64 + 56 = 120 if input present
  const inputOffset = req.input.length > 0 ? 64 + 56 : 0;
  w.u32(inputOffset);
  w.u32(req.input.length);
  w.u32(req.maxInputResponse ?? 0);
  w.u32(0); // OutputOffset
  w.u32(0); // OutputCount
  w.u32(req.maxOutputResponse);
  w.u32(req.flags);
  w.u32(0); // Reserved2
  if (req.input.length > 0) w.bytes(req.input);
  else w.u8(0);
  return w.buffer();
}

export function decodeIoctlResponse(body: Buffer, bodyAt = 64): Buffer {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== 49) throw new Error(`IOCTL resp StructureSize ${ss} != 49`);
  r.u16(); // Reserved
  r.u32(); // CtlCode
  r.bytes(16); // FileId
  r.u32(); // InputOffset
  r.u32(); // InputCount
  const outOffset = r.u32();
  const outCount = r.u32();
  r.u32(); // Flags
  r.u32(); // Reserved2
  const start = outOffset - bodyAt;
  return Buffer.from(body.subarray(start, start + outCount));
}
