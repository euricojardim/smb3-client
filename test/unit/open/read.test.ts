import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Open } from "../../../src/open/open.js";
import { Tree } from "../../../src/tree/tree.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { readAll } from "../../../src/open/read.js";

function readResp(messageId: bigint, sessionId: bigint, treeId: number, payload: Buffer): Buffer {
  const w = new Writer();
  w.u16(17);
  const dataOffset = 64 + 16;
  w.u8(dataOffset); w.u8(0);
  w.u32(payload.length);
  w.u32(0); w.u32(0);
  w.bytes(payload);
  const hdr = encodeHeader({
    command: SmbCommand.READ, creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
    messageId, sessionId, treeId, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

describe("readAll", () => {
  it("chunks reads above maxReadSize and concatenates results", async () => {
    const ft = new FakeTransport();
    let calls = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.READ) return;
      const messageId = smb.readBigUInt64LE(24);
      // body starts at offset 64; READ body fields: StructureSize(2) Padding(1) Reserved(1) Length(4) Offset(8)
      const length = smb.readUInt32LE(64 + 4);
      const offset = smb.readBigUInt64LE(64 + 8);
      const buf = Buffer.alloc(length);
      for (let i = 0; i < length; i++) buf[i] = (Number(offset & 0xffn) + i) & 0xff;
      calls++;
      ft.deliver(readResp(messageId, 0xabcdn, 0x42, buf));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1, maxReadSize: 100 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn,
      session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const fid = Buffer.alloc(16, 0xfe);
    const open = new (Open as unknown as { new (...args: unknown[]): Open })(tree, fid, {} as never);
    const out = await readAll(open, 250n);
    expect(out.length).toBe(250);
    expect(calls).toBe(3); // 100 + 100 + 50
    // Verify byte pattern
    expect(out[0]).toBe(0);
    expect(out[100]).toBe(100);
    expect(out[200]).toBe(200);
  });
});
