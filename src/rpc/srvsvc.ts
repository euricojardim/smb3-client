import { Reader, Writer } from "../wire/buffer.js";
import { encodeBindRequest, parseBindAck, encodeRequest, parseResponse } from "./dcerpc.js";

export const SRVSVC_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
export const SRVSVC_MAJOR = 3;
export const SRVSVC_MINOR = 0;

let referentCounter = 0x20000;

function newReferent(): number {
  referentCounter += 4;
  return referentCounter;
}

function ndrUtf16(s: string): Buffer {
  // NDR conformant+varying string: max(4) offset(4) actual(4) chars(2*actual) padded to 4
  const w = new Writer();
  const ws = s + "\0";
  const max = ws.length;
  w.u32(max);
  w.u32(0);
  w.u32(max);
  w.utf16(ws);
  while (w.offset % 4 !== 0) w.u8(0);
  return w.buffer();
}

export interface NetrShareEnumRequest {
  serverName: string; // "\\\\srv"
  infoLevel: number;
  preferredMaximumLength: number;
}

export function encodeNetrShareEnumRequest(req: NetrShareEnumRequest): Buffer {
  const w = new Writer();
  // ServerName: pointer to wstring
  const ptr = newReferent();
  w.u32(ptr); // Referent
  w.bytes(ndrUtf16(req.serverName));
  // SHARE_ENUM_STRUCT: Level (4), pointer to union (4)
  w.u32(req.infoLevel);
  w.u32(req.infoLevel); // tag again
  const arrPtr = newReferent();
  w.u32(arrPtr);
  // SHARE_INFO_1_CONTAINER: EntriesRead (4), pointer to Buffer (4) = NULL on enumerate request
  w.u32(0);
  w.u32(0);
  // PreferedMaximumLength
  w.u32(req.preferredMaximumLength);
  // ResumeHandle: pointer to ULONG; pass NULL pointer
  w.u32(0);
  return w.buffer();
}

export interface ShareEntry {
  name: string;
  type: number;
  comment: string;
}

export function parseNetrShareEnumResponse(stub: Buffer): { entries: ShareEntry[]; status: number } {
  if (stub.length < 4) return { entries: [], status: 0 };
  const r = new Reader(stub);
  // Level
  r.u32();
  // Union tag
  if (r.remaining() < 4) return { entries: [], status: 0 };
  r.u32();
  // Pointer to container
  if (r.remaining() < 4) return { entries: [], status: 0 };
  const containerPtr = r.u32();
  if (containerPtr === 0) {
    // Skip ahead to status.
    while (r.remaining() > 4) r.u32();
    const status = r.remaining() >= 4 ? r.u32() : 0;
    return { entries: [], status };
  }
  if (r.remaining() < 8) return { entries: [], status: 0 };
  const entriesRead = r.u32();
  const arrPtr = r.u32();
  if (arrPtr === 0 || entriesRead === 0) {
    return { entries: [], status: 0 };
  }
  // Conformant array header: MaxCount
  if (r.remaining() < 4) return { entries: [], status: 0 };
  r.u32();
  // For each entry: name pointer (4), type (4), comment pointer (4)
  const entries: { namePtr: number; type: number; commentPtr: number }[] = [];
  for (let i = 0; i < entriesRead; i++) {
    if (r.remaining() < 12) break;
    const namePtr = r.u32();
    const type = r.u32();
    const commentPtr = r.u32();
    entries.push({ namePtr, type, commentPtr });
  }
  // Then deferred strings, in order: name then comment for each non-null pointer
  const out: ShareEntry[] = [];
  for (const e of entries) {
    let name = "";
    if (e.namePtr !== 0 && r.remaining() >= 12) {
      const max = r.u32();
      r.u32(); // offset
      const actual = r.u32();
      if (r.remaining() >= actual * 2) {
        name = r.utf16(actual * 2).replace(/\0+$/, "").trimEnd();
        while (r.offset % 4 !== 0 && r.remaining() > 0) r.u8();
      }
      void max;
    }
    let comment = "";
    if (e.commentPtr !== 0 && r.remaining() >= 12) {
      const max = r.u32();
      r.u32();
      const actual = r.u32();
      if (r.remaining() >= actual * 2) {
        comment = r.utf16(actual * 2).replace(/\0+$/, "").trimEnd();
        while (r.offset % 4 !== 0 && r.remaining() > 0) r.u8();
      }
      void max;
    }
    out.push({ name, type: e.type, comment });
  }
  // TotalEntries (4) + ResumeHandle pointer (4) [+ optional handle] + Status (4)
  while (r.remaining() > 4) r.u32();
  const status = r.remaining() >= 4 ? r.u32() : 0;
  return { entries: out, status };
}

export { encodeBindRequest, parseBindAck, encodeRequest, parseResponse };
