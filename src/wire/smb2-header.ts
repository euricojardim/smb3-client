import { Reader, Writer } from "./buffer.js";
import { HeaderFlag } from "./commands.js";

export interface SmbHeader {
  command: number;
  creditCharge: number;
  creditRequestResponse: number;
  flags: number;
  messageId: bigint;
  sessionId: bigint;
  status: number;
  // SYNC
  treeId?: number;
  // ASYNC
  asyncId?: bigint;
  signature?: Buffer;
  nextCommand?: number;
}

const PROTOCOL_ID = Buffer.from([0xfe, 0x53, 0x4d, 0x42]); // "\xFESMB"
export const SMB2_HEADER_SIZE = 64;

export function encodeHeader(h: SmbHeader): Buffer {
  const w = new Writer();
  w.bytes(PROTOCOL_ID);
  w.u16(SMB2_HEADER_SIZE); // StructureSize
  w.u16(h.creditCharge);
  w.u32(h.status >>> 0); // Channel sequence + reserved on send for 3.x; status on recv
  w.u16(h.command);
  w.u16(h.creditRequestResponse);
  w.u32(h.flags >>> 0);
  w.u32(h.nextCommand ?? 0);
  w.u64(h.messageId);
  if (h.flags & HeaderFlag.ASYNC_COMMAND) {
    if (h.asyncId === undefined) throw new Error("encodeHeader: asyncId required when ASYNC flag set");
    w.u64(h.asyncId);
  } else {
    w.u32(0); // Reserved
    w.u32(h.treeId ?? 0);
  }
  w.u64(h.sessionId);
  if (h.signature) {
    if (h.signature.length !== 16) throw new Error("signature must be 16 bytes");
    w.bytes(h.signature);
  } else {
    w.pad(16);
  }
  return w.buffer();
}

export function decodeHeader(buf: Buffer): { header: SmbHeader; bodyOffset: number; isAsync: boolean } {
  if (buf.length < SMB2_HEADER_SIZE) {
    throw new RangeError(`SMB2 header too short: ${buf.length}`);
  }
  if (!buf.subarray(0, 4).equals(PROTOCOL_ID)) {
    throw new Error("decodeHeader: bad protocol id");
  }
  const r = new Reader(buf);
  r.bytes(4); // protocol id
  const structureSize = r.u16();
  if (structureSize !== SMB2_HEADER_SIZE) {
    throw new Error(`decodeHeader: unexpected StructureSize ${structureSize}`);
  }
  const creditCharge = r.u16();
  const status = r.u32();
  const command = r.u16();
  const creditRequestResponse = r.u16();
  const flags = r.u32();
  const nextCommand = r.u32();
  const messageId = r.u64();
  const isAsync = (flags & HeaderFlag.ASYNC_COMMAND) !== 0;
  let treeId: number | undefined;
  let asyncId: bigint | undefined;
  if (isAsync) {
    asyncId = r.u64();
  } else {
    r.u32(); // Reserved
    treeId = r.u32();
  }
  const sessionId = r.u64();
  const signature = r.bytes(16);
  const base = {
    command,
    creditCharge,
    creditRequestResponse,
    flags,
    messageId,
    sessionId,
    status,
    nextCommand,
    signature,
  };
  const header: SmbHeader = isAsync
    ? { ...base, asyncId: asyncId! }
    : { ...base, treeId: treeId! };
  return { header, bodyOffset: SMB2_HEADER_SIZE, isAsync };
}
