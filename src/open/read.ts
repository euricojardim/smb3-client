import type { Open } from "./open.js";
import { encodeReadRequest, decodeReadResponse } from "../wire/structs/read.js";
import { SmbCommand, NTStatus, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

const DEFAULT_CHUNK = 1 << 16; // 64 KiB

export async function readAll(open: Open, length: bigint): Promise<Buffer> {
  const max = open.tree.conn.state?.maxReadSize ?? DEFAULT_CHUNK;
  const chunkSize = Math.min(max, 1 << 20); // cap at 1 MiB chunks for simplicity
  const out: Buffer[] = [];
  let offset = 0n;
  let remaining = length;
  while (remaining > 0n) {
    const want = Number(remaining > BigInt(chunkSize) ? BigInt(chunkSize) : remaining);
    const chunk = await readAt(open, offset, want);
    if (chunk.length === 0) break;
    out.push(chunk);
    offset += BigInt(chunk.length);
    remaining -= BigInt(chunk.length);
  }
  return Buffer.concat(out);
}

export async function readAt(open: Open, offset: bigint, length: number): Promise<Buffer> {
  const charge = Math.max(1, Math.ceil(length / 65536));
  const body = encodeReadRequest({ fileId: open.fileId, offset, length });
  const signing = open.tree.session.makeSigning();
  const resp = await open.tree.conn.send(SmbCommand.READ, body, {
    sessionId: open.tree.session.sessionId,
    treeId: open.tree.treeId,
    ...(signing !== undefined ? { signing } : {}),
    creditCharge: charge,
  });
  if (resp.header.status === NTStatus.STATUS_END_OF_FILE) return Buffer.alloc(0);
  if (!isSuccess(resp.header.status)) {
    throw new SmbError({ status: resp.header.status, message: `READ failed: ${statusName(resp.header.status)}` });
  }
  return decodeReadResponse(resp.body, 64);
}
