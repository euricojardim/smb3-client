import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { sign } from "../../../src/connection/signing.js";
import { Dialect, SmbCommand, HeaderFlag } from "../../../src/wire/commands.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { SmbProtocolError } from "../../../src/errors.js";

const TEST_DIALECT = Dialect.SMB_3_1_1;
const TEST_KEY = Buffer.alloc(16, 0xcc);

/** Build a minimal SMB2 response frame for the given command/messageId, with optional SIGNED flag. */
function makeResponseFrame(opts: {
  command: number;
  messageId: bigint;
  signed: boolean;
  key?: Buffer;
  dialect?: number;
  tamper?: boolean;
}): Buffer {
  const { command, messageId, signed, key, dialect = TEST_DIALECT, tamper = false } = opts;
  const flags = HeaderFlag.SERVER_TO_REDIR | (signed ? HeaderFlag.SIGNED : 0);
  const hdr = encodeHeader({
    command,
    creditCharge: 1,
    creditRequestResponse: 1,
    flags,
    messageId,
    sessionId: 1n,
    treeId: 0,
    status: 0,
  });
  // A minimal 4-byte body (LOGOFF response structureSize=4).
  const body = Buffer.from([0x04, 0x00, 0x00, 0x00]);
  const frame = Buffer.concat([hdr, body]);

  if (signed && key) {
    // Zero the signature field (bytes 48..64) and compute signature over the full frame.
    const working = Buffer.from(frame);
    working.fill(0, 48, 64);
    const sig = sign(working, key, dialect);
    if (tamper) {
      // Corrupt the last byte of the signature.
      sig[15] = sig[15]! ^ 0xff;
    }
    sig.copy(frame, 48);
  }

  return frame;
}

describe("Connection signature verification", () => {
  it("delivers a properly-signed response when verifier is set", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: TEST_DIALECT };

    // Register a verifier using the test key.
    conn.setVerifier((frame, sig) => {
      const working = Buffer.from(frame);
      working.fill(0, 48, 64);
      return sign(working, TEST_KEY, TEST_DIALECT).equals(sig);
    });

    // Send a request to create a pending entry (messageId = 0).
    const responseReceived = conn.send(SmbCommand.LOGOFF, Buffer.from([0x04, 0x00, 0x00, 0x00]));

    // Build a properly-signed response.
    const frame = makeResponseFrame({
      command: SmbCommand.LOGOFF,
      messageId: 0n,
      signed: true,
      key: TEST_KEY,
    });
    ft.deliver(frame);

    // Should resolve successfully.
    const result = await responseReceived;
    expect(result.header.command).toBe(SmbCommand.LOGOFF);
  });

  it("fails the connection when a tampered signature is received", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: TEST_DIALECT };

    conn.setVerifier((frame, sig) => {
      const working = Buffer.from(frame);
      working.fill(0, 48, 64);
      return sign(working, TEST_KEY, TEST_DIALECT).equals(sig);
    });

    const responseReceived = conn.send(SmbCommand.LOGOFF, Buffer.from([0x04, 0x00, 0x00, 0x00]));

    // Build a tampered response (bad signature).
    const frame = makeResponseFrame({
      command: SmbCommand.LOGOFF,
      messageId: 0n,
      signed: true,
      key: TEST_KEY,
      tamper: true,
    });
    ft.deliver(frame);

    // The pending promise should reject with SmbProtocolError.
    await expect(responseReceived).rejects.toBeInstanceOf(SmbProtocolError);
    await expect(responseReceived).rejects.toMatchObject({ message: "signature verify failed" });
  });

  it("delivers a non-signed response without attempting verification (no verifier)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: TEST_DIALECT };
    // No verifier registered.

    const responseReceived = conn.send(SmbCommand.LOGOFF, Buffer.from([0x04, 0x00, 0x00, 0x00]));

    // Build an unsigned response (no SIGNED flag).
    const frame = makeResponseFrame({
      command: SmbCommand.LOGOFF,
      messageId: 0n,
      signed: false,
    });
    ft.deliver(frame);

    const result = await responseReceived;
    expect(result.header.command).toBe(SmbCommand.LOGOFF);
  });

  it("delivers a non-signed response without verification even when verifier is set", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: TEST_DIALECT };

    let verifierCalled = false;
    conn.setVerifier((_frame, _sig) => {
      verifierCalled = true;
      return true;
    });

    const responseReceived = conn.send(SmbCommand.LOGOFF, Buffer.from([0x04, 0x00, 0x00, 0x00]));

    // Build an unsigned response (no SIGNED flag).
    const frame = makeResponseFrame({
      command: SmbCommand.LOGOFF,
      messageId: 0n,
      signed: false,
    });
    ft.deliver(frame);

    const result = await responseReceived;
    expect(result.header.command).toBe(SmbCommand.LOGOFF);
    expect(verifierCalled).toBe(false);
  });
});
