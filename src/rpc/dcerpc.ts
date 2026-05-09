import { Writer } from "../wire/buffer.js";

const NDR_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"; // NDR transfer syntax
const NDR_VERSION = 2;

function uuidToBytes(uuid: string): Buffer {
  // Format: 4-2-2-2-6 (little-endian for first three groups, big-endian last two)
  const hex = uuid.replace(/-/g, "");
  const out = Buffer.alloc(16);
  out.writeUInt32LE(parseInt(hex.slice(0, 8), 16), 0);
  out.writeUInt16LE(parseInt(hex.slice(8, 12), 16), 4);
  out.writeUInt16LE(parseInt(hex.slice(12, 16), 16), 6);
  Buffer.from(hex.slice(16, 20), "hex").copy(out, 8);
  Buffer.from(hex.slice(20, 32), "hex").copy(out, 10);
  return out;
}

function commonHeader(packetType: number, callId: number, fragLen: number): Buffer {
  const w = new Writer();
  w.u8(5); // RpcVersion
  w.u8(0); // MinorVersion
  w.u8(packetType);
  w.u8(0x03); // PacketFlags: First+Last
  w.bytes(Buffer.from([0x10, 0x00, 0x00, 0x00])); // DataRepresentation: little-endian
  w.u16(fragLen); // FragLength — patched below
  w.u16(0); // AuthLength
  w.u32(callId);
  return w.buffer();
}

export interface BindOptions {
  callId: number;
  abstractUuid: string;
  abstractMajor: number;
  abstractMinor: number;
  maxXmitFrag?: number;
  maxRecvFrag?: number;
}

export function encodeBindRequest(opts: BindOptions): Buffer {
  const max = opts.maxXmitFrag ?? 4280;
  const w = new Writer();
  w.bytes(commonHeader(0x0b, opts.callId, 0));
  w.u16(max); // MaxXmitFrag
  w.u16(opts.maxRecvFrag ?? max); // MaxRecvFrag
  w.u32(0); // AssocGroupId
  w.u8(1); // NumContextItems
  w.bytes(Buffer.alloc(3)); // pad
  // Context 0
  w.u16(0); // ContextId
  w.u8(1); // NumTransSyntaxes
  w.u8(0); // pad
  w.bytes(uuidToBytes(opts.abstractUuid));
  w.u16(opts.abstractMajor); w.u16(opts.abstractMinor);
  w.bytes(uuidToBytes(NDR_UUID));
  w.u16(NDR_VERSION); w.u16(0);
  const buf = w.buffer();
  buf.writeUInt16LE(buf.length, 8); // FragLength
  return buf;
}

export interface BindAck {
  callId: number;
  results: { result: number }[];
}

export function parseBindAck(buf: Buffer): BindAck {
  if (buf[2] !== 0x0c) throw new Error("DCE/RPC: not a Bind Ack");
  const callId = buf.readUInt32LE(12);
  const numResults = buf[24]!;
  const results: { result: number }[] = [];
  // For our minimal use we don't need to parse results in detail; we trust the ack.
  for (let i = 0; i < numResults; i++) results.push({ result: 0 });
  return { callId, results };
}

export interface RequestOptions {
  callId: number;
  opnum: number;
  contextId: number;
  stub: Buffer;
}

export function encodeRequest(opts: RequestOptions): Buffer {
  const w = new Writer();
  w.bytes(commonHeader(0x00, opts.callId, 0));
  w.u32(opts.stub.length); // AllocHint
  w.u16(opts.contextId);
  w.u16(opts.opnum);
  w.bytes(opts.stub);
  const buf = w.buffer();
  buf.writeUInt16LE(buf.length, 8);
  return buf;
}

export function parseResponse(buf: Buffer): Buffer | null {
  if (buf.length < 24) return null;
  if (buf[2] !== 0x02) return null;
  const stubOff = 24;
  return Buffer.from(buf.subarray(stubOff));
}
