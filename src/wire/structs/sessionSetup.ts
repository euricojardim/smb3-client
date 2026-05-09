import { Reader, Writer } from "../buffer.js";

export interface SessionSetupRequest {
  flags?: number;
  securityMode: number;
  capabilities: number;
  channel?: number;
  previousSessionId?: bigint;
  blob: Buffer;
}

const REQ_STRUCT_SIZE = 25;

export function encodeSessionSetupRequest(req: SessionSetupRequest): Buffer {
  const w = new Writer();
  const blobOffset = 64 + REQ_STRUCT_SIZE - 1; // -1 because of "1-based" StructureSize convention; effectively contiguous
  w.u16(REQ_STRUCT_SIZE);
  w.u8(req.flags ?? 0);
  w.u8(req.securityMode);
  w.u32(req.capabilities);
  w.u32(req.channel ?? 0);
  w.u16(blobOffset); // SecurityBufferOffset (from header start)
  w.u16(req.blob.length);
  w.u64(req.previousSessionId ?? 0n);
  w.bytes(req.blob);
  return w.buffer();
}

export interface SessionSetupResponse {
  sessionFlags: number;
  securityBuffer: Buffer;
}

const RESP_STRUCT_SIZE = 9;

export function decodeSessionSetupResponse(body: Buffer, bodyAt = 64): SessionSetupResponse {
  const r = new Reader(body);
  const ss = r.u16();
  if (ss !== RESP_STRUCT_SIZE) throw new Error(`SESSION_SETUP resp StructureSize ${ss} != 9`);
  const sessionFlags = r.u16();
  const offset = r.u16();
  const length = r.u16();
  const start = offset - bodyAt;
  const securityBuffer = length > 0 ? Buffer.from(body.subarray(start, start + length)) : Buffer.alloc(0);
  return { sessionFlags, securityBuffer };
}
