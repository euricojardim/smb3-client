import { describe, it, expect } from "vitest";
import { Tree } from "../../../src/tree/tree.js";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session } from "../../../src/session/session.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";

describe("Tree.connect", () => {
  it("acquires a TreeId and exposes shareType", async () => {
    const ft = new FakeTransport();
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      const messageId = smb.readBigUInt64LE(24);
      const cmd = smb.readUInt16LE(12);
      if (cmd === SmbCommand.TREE_CONNECT) {
        const body = new Writer();
        body.u16(16); body.u8(1); body.u8(0); body.u32(0); body.u32(0); body.u32(0);
        const hdr = encodeHeader({
          command: SmbCommand.TREE_CONNECT,
          creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
          messageId, sessionId: 0xabcdn, treeId: 0x42, status: 0,
        });
        ft.deliver(Buffer.concat([hdr, body.buffer()]));
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sess = Object.assign(Object.create(Session.prototype), {
      sessionId: 0xabcdn, signingKey: Buffer.alloc(16, 0xab), conn,
      makeSigning: () => undefined, // skip signing for this test
    }) as Session;
    const tree = await Tree.connect(conn, sess, "\\\\srv\\share");
    expect(tree.treeId).toBe(0x42);
    expect(tree.shareType).toBe("disk");
  });
});
