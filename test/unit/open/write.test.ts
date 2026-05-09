import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { writeAll } from "../../../src/open/write.js";

function writeResp(messageId: bigint, sessionId: bigint, treeId: number, count: number): Buffer {
  const w = new Writer();
  w.u16(17); w.u16(0); w.u32(count); w.u32(0); w.u16(0); w.u16(0);
  const hdr = encodeHeader({
    command: SmbCommand.WRITE, creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId, treeId, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("writeAll", () => {
  it("chunks above maxWriteSize and writes all bytes", async () => {
    const ft = new FakeTransport();
    let totalCount = 0;
    let calls = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.WRITE) return;
      const messageId = smb.readBigUInt64LE(24);
      const len = smb.readUInt32LE(64 + 4);
      totalCount += len;
      calls++;
      ft.deliver(writeResp(messageId, 0xabcdn, 0x42, len));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxWriteSize: 100 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    await writeAll(open, 0n, Buffer.alloc(250, 0x77));
    expect(totalCount).toBe(250);
    expect(calls).toBe(3);
  });
});
