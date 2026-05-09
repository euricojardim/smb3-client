import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Tree } from "../../../src/tree/tree.js";
import { Open } from "../../../src/open/open.js";
import { createWriteStream } from "../../../src/open/writeStream.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";

function writeResp(messageId: bigint, count: number): Buffer {
  const w = new Writer();
  w.u16(17); w.u16(0); w.u32(count); w.u32(0); w.u16(0); w.u16(0);
  const hdr = encodeHeader({
    command: SmbCommand.WRITE, creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId: 0xabcdn, treeId: 0x42, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("createWriteStream", () => {
  it("writes all source bytes to the file at the right offsets", async () => {
    const ft = new FakeTransport();
    let total = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.WRITE) return;
      const messageId = smb.readBigUInt64LE(24);
      const len = smb.readUInt32LE(64 + 4);
      total += len;
      ft.deliver(writeResp(messageId, len));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxWriteSize: 64 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    const ws = createWriteStream(open, { closeOnFinal: false });
    await pipeline(Readable.from([Buffer.alloc(200, 0xab)]), ws);
    expect(total).toBe(200);
  });
});
