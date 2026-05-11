import { describe, it, expect } from "vitest";
import { Tree } from "../../../src/tree/tree.js";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session } from "../../../src/session/session.js";
import { Dialect, ShareFlag, SmbCommand } from "../../../src/wire/commands.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";

function fakeTreeConnectServer(
  ft: FakeTransport,
  shareFlags: number,
  treeId = 0x42,
  sessionId = 0xabcdn,
): void {
  ft.onSend((frame) => {
    const smb = frame.subarray(4);
    const messageId = smb.readBigUInt64LE(24);
    const cmd = smb.readUInt16LE(12);
    if (cmd === SmbCommand.TREE_CONNECT) {
      const body = new Writer();
      body.u16(16); body.u8(1); body.u8(0); body.u32(shareFlags); body.u32(0); body.u32(0);
      const hdr = encodeHeader({
        command: SmbCommand.TREE_CONNECT,
        creditCharge: 1, creditRequestResponse: 1, flags: 0x1,
        messageId, sessionId, treeId, status: 0,
      });
      ft.deliver(Buffer.concat([hdr, body.buffer()]));
    }
  });
}

function makeSess(conn: Connection, overrides: Partial<Session> = {}): Session {
  return Object.assign(Object.create(Session.prototype), {
    sessionId: 0xabcdn,
    signingKey: Buffer.alloc(16, 0xab),
    encryptionKeys: null,
    globalEncrypt: false,
    conn,
    makeSigning: () => undefined,
    ...overrides,
  }) as Session;
}

describe("Tree.connect", () => {
  it("acquires a TreeId and exposes shareType", async () => {
    const ft = new FakeTransport();
    fakeTreeConnectServer(ft, 0);
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sess = makeSess(conn);
    const tree = await Tree.connect(conn, sess, "\\\\srv\\share");
    expect(tree.treeId).toBe(0x42);
    expect(tree.shareType).toBe("disk");
    expect(tree.encryptData).toBe(false);
    expect(tree.encryptRequired).toBe(false);
  });

  it("marks encryptData=true when ENCRYPT_DATA share flag is set and session has keys", async () => {
    const ft = new FakeTransport();
    fakeTreeConnectServer(ft, ShareFlag.ENCRYPT_DATA);
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sess = makeSess(conn, {
      encryptionKeys: { encryption: Buffer.alloc(16), decryption: Buffer.alloc(16), cipherId: 1 },
    } as Partial<Session>);
    const tree = await Tree.connect(conn, sess, "\\\\srv\\share");
    expect(tree.encryptData).toBe(true);
    expect(tree.encryptRequired).toBe(true);
  });

  it("throws when share requires encryption but session has no keys", async () => {
    const ft = new FakeTransport();
    fakeTreeConnectServer(ft, ShareFlag.ENCRYPT_DATA);
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sess = makeSess(conn); // encryptionKeys: null
    await expect(Tree.connect(conn, sess, "\\\\srv\\share")).rejects.toThrow(/encryption/);
  });
});
