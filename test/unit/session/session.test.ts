import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session } from "../../../src/session/session.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, NTStatus, SmbCommand } from "../../../src/wire/commands.js";
import { wrapInitNegToken, wrapNegTokenResp } from "../../../src/session/spnego.js";

function chalMessage(): Buffer {
  const w = new Writer();
  w.bytes(Buffer.from("NTLMSSP\0"));
  w.u32(2);
  w.u16(0); w.u16(0); w.u32(0);
  w.u32(0);
  w.bytes(Buffer.from("0123456789abcdef", "hex"));
  w.bytes(Buffer.alloc(8));
  const ti = Buffer.from("00000000", "hex");
  const tiOff = 56;
  w.u16(ti.length); w.u16(ti.length); w.u32(tiOff);
  w.bytes(Buffer.alloc(8));
  w.bytes(ti);
  return w.buffer();
}

function ssRespFrame(messageId: bigint, sessionId: bigint, status: number, blob: Buffer): Buffer {
  const body = new Writer();
  body.u16(9);
  body.u16(0);
  const off = 64 + 8;
  body.u16(off);
  body.u16(blob.length);
  body.bytes(blob);
  const hdr = encodeHeader({
    command: SmbCommand.SESSION_SETUP,
    creditCharge: 1,
    creditRequestResponse: 1,
    flags: 0x00000001,
    messageId,
    sessionId,
    treeId: 0,
    status,
  });
  return Buffer.concat([hdr, body.buffer()]);
}

describe("Session.setup", () => {
  it("walks NEG → CHAL → AUTH and yields STATUS_SUCCESS", async () => {
    const ft = new FakeTransport();
    let step = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      const msgId = smb.readBigUInt64LE(24);
      if (smb.readUInt16LE(12) === SmbCommand.NEGOTIATE) {
        // Build minimal 3.1.1 negotiate response (reuse from T1.12 pattern omitted for brevity:
        // just send empty/skeleton for T2.7 purposes — Connection.open already covered).
        // For this test we manually pre-set Connection.negotiated to skip NEGOTIATE.
        return;
      }
      if (smb.readUInt16LE(12) === SmbCommand.SESSION_SETUP) {
        if (step === 0) {
          step++;
          ft.deliver(ssRespFrame(msgId, 0xabcdn, NTStatus.STATUS_MORE_PROCESSING_REQUIRED, wrapInitNegToken(chalMessage())));
        } else {
          ft.deliver(ssRespFrame(msgId, 0xabcdn, 0, wrapNegTokenResp(Buffer.alloc(0))));
        }
      }
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      preauthHashAlg: 1,
      preauthSalt: Buffer.alloc(32),
      securityBuffer: Buffer.alloc(0),
      maxReadSize: 65536,
      maxWriteSize: 65536,
      maxTransactSize: 65536,
      capabilities: 0,
      securityMode: 1,
      serverGuid: Buffer.alloc(16),
    };
    const sess = new Session(conn, { username: "User", password: "Password", domain: "Domain" });
    await sess.setup();
    expect(sess.sessionId).toBe(0xabcdn);
    expect(sess.signingKey?.length).toBe(16);
  });
});
