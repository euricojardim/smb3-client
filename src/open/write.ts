import type { Open } from "./open.js";
import { encodeWriteRequest, decodeWriteResponse } from "../wire/structs/write.js";
import { SmbCommand, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

export async function writeAll(open: Open, offset: bigint, data: Buffer): Promise<void> {
  // Cap at 65536 so that creditCharge is always 1, keeping the credit window
  // from stalling (the client starts with only a handful of credits and the
  // server grants exactly creditRequestResponse=1 credit per response).
  const max = open.tree.conn.state?.maxWriteSize ?? 65536;
  const chunkSize = Math.min(max, 65536);
  let written = 0;
  while (written < data.length) {
    const chunk = data.subarray(written, written + Math.min(chunkSize, data.length - written));
    const charge = Math.max(1, Math.ceil(chunk.length / 65536));
    const body = encodeWriteRequest({
      fileId: open.fileId,
      offset: offset + BigInt(written),
      data: Buffer.from(chunk),
    });
    const signing = open.tree.session.makeSigning();
    const resp = await open.tree.conn.send(SmbCommand.WRITE, body, {
      sessionId: open.tree.session.sessionId,
      treeId: open.tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: open.tree.encryptRequired,
      creditCharge: charge,
    });
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `WRITE failed: ${statusName(resp.header.status)}` });
    }
    const count = decodeWriteResponse(resp.body);
    if (count <= 0) throw new Error("WRITE returned zero count");
    written += count;
  }
}
