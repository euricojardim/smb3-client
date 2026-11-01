import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, NegotiateContextType, SmbCommand } from "../../../src/wire/commands.js";

function buildNegotiateResponseFrame(messageId: bigint): Buffer {
  // Body
  const body = new Writer();
  body.u16(65); // StructureSize
  body.u16(1); // SecurityMode (signing enabled)
  body.u16(Dialect.SMB_3_1_1);
  body.u16(1); // contextCount
  body.bytes(Buffer.alloc(16, 0xee));
  body.u32(0);
  body.u32(8 * 1024 * 1024);
  body.u32(8 * 1024 * 1024);
  body.u32(8 * 1024 * 1024);
  body.u64(0n);
  body.u64(0n);
  body.u16(0); body.u16(0); // sec buf offset/length
  const ctxOffPatch = body.offset;
  body.u32(0);
  body.padTo(8);
  const ctxStart = body.offset;
  body.u16(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES);
  body.u16(2 + 2 + 2 + 32);
  body.u32(0);
  body.u16(1);
  body.u16(32);
  body.u16(1);
  body.bytes(Buffer.alloc(32, 0x77));
  body.padTo(8);
  const bodyBuf = body.buffer();
  bodyBuf.writeUInt32LE(64 + ctxStart, ctxOffPatch);

  const hdr = encodeHeader({
    command: SmbCommand.NEGOTIATE,
    creditCharge: 1,
    creditRequestResponse: 1,
    flags: 0x00000001, // SERVER_TO_REDIR
    messageId,
    sessionId: 0n,
    treeId: 0,
    status: 0,
  });
  return Buffer.concat([hdr, bodyBuf]);
}

describe("Connection.open (negotiate)", () => {
  it("sends NEGOTIATE and resolves with the agreed dialect", async () => {
    const ft = new FakeTransport();
    ft.onSend((frame) => {
      // Strip 4-byte length header to find the SMB2 frame.
      const smb = frame.subarray(4);
      const messageId = smb.readBigUInt64LE(24);
      ft.deliver(buildNegotiateResponseFrame(messageId));
    });
    const conn = new Connection(ft);
    const result = await conn.open({ clientGuid: Buffer.alloc(16, 0x55) });
    expect(result.dialect).toBe(Dialect.SMB_3_1_1);
    expect(result.maxReadSize).toBe(8 * 1024 * 1024);
    expect(result.preauthSalt?.length).toBe(32);
  });
});

describe("Connection.open (credits)", () => {
  it("counts the initial credit used by NEGOTIATE", async () => {
    const ft = new FakeTransport();
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      ft.deliver(buildNegotiateResponseFrame(smb.readBigUInt64LE(24)));
    });
    const conn = new Connection(ft);
    await conn.open();
    // The server granted one credit in its response, and the one the connection
    // started with went to NEGOTIATE: one left, as the server sees it.
    const credits = (conn as unknown as { credits: { available(): number } }).credits;
    expect(credits.available()).toBe(1);
  });
});
