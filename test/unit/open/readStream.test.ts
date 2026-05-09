import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Tree } from "../../../src/tree/tree.js";
import { Open } from "../../../src/open/open.js";
import { createReadStream } from "../../../src/open/readStream.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";

function readResp(messageId: bigint, payload: Buffer): Buffer {
  const w = new Writer();
  w.u16(17);
  const dataOffset = 64 + 16;
  w.u8(dataOffset); w.u8(0);
  w.u32(payload.length);
  w.u32(0); w.u32(0);
  w.bytes(payload);
  const hdr = encodeHeader({
    command: SmbCommand.READ, creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId: 0xabcdn, treeId: 0x42, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("createReadStream", () => {
  it("yields all bytes in order", async () => {
    const ft = new FakeTransport();
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.READ) return;
      const messageId = smb.readBigUInt64LE(24);
      const length = smb.readUInt32LE(64 + 4);
      const offset = smb.readBigUInt64LE(64 + 8);
      const buf = Buffer.alloc(length);
      for (let i = 0; i < length; i++) buf[i] = (Number(offset & 0xffn) + i) & 0xff;
      ft.deliver(readResp(messageId, buf));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxReadSize: 100 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), { endOfFile: 250n } as never);
    const rs = createReadStream(open);
    const chunks: Buffer[] = [];
    for await (const c of rs) chunks.push(c as Buffer);
    const all = Buffer.concat(chunks);
    expect(all.length).toBe(250);
    expect(all[0]).toBe(0);
    expect(all[100]).toBe(100);
    expect(all[200]).toBe(200);
  });
});
