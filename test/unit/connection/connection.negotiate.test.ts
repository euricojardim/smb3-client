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

function buildNegotiateResponse202(messageId: bigint): Buffer {
  const body = new Writer();
  body.u16(65); // StructureSize
  body.u16(1); // SecurityMode
  body.u16(Dialect.SMB_2_0_2);
  body.u16(0); // NegotiateContextCount (reserved before 3.1.1)
  body.bytes(Buffer.alloc(16, 0xee));
  body.u32(0); // Capabilities
  body.u32(65536); body.u32(65536); body.u32(65536);
  body.u64(0n); body.u64(0n);
  body.u16(0); body.u16(0); // security buffer
  body.u32(0);
  const hdr = encodeHeader({
    command: SmbCommand.NEGOTIATE, creditCharge: 0, creditRequestResponse: 1, flags: 0x00000001,
    messageId, sessionId: 0n, treeId: 0, status: 0,
  });
  return Buffer.concat([hdr, body.buffer()]);
}

describe("Connection (SMB 2.0.2)", () => {
  it("offers 2.0.2 and, once agreed, sends CreditCharge 0", async () => {
    const ft = new FakeTransport();
    const charges: number[] = [];
    let offered: number[] = [];
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      const command = smb.readUInt16LE(12);
      charges.push(smb.readUInt16LE(6));
      if (command === SmbCommand.NEGOTIATE) {
        const count = smb.readUInt16LE(64 + 2);
        offered = Array.from({ length: count }, (_, i) => smb.readUInt16LE(64 + 36 + i * 2));
        ft.deliver(buildNegotiateResponse202(smb.readBigUInt64LE(24)));
      }
    });
    const conn = new Connection(ft);
    const result = await conn.open();
    expect(offered).toContain(Dialect.SMB_2_0_2);
    expect(result.dialect).toBe(Dialect.SMB_2_0_2);
    void conn.send(SmbCommand.ECHO, Buffer.from([4, 0, 0, 0]), { creditCharge: 1 }).catch(() => undefined);
    await new Promise((r) => setTimeout(r, 0));
    expect(charges[charges.length - 1]).toBe(0);
    conn.close();
  });
});
