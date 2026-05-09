import { describe, it, expect } from "vitest";
import { encodeHeader, decodeHeader } from "../../../src/wire/smb2-header.js";
import { SmbCommand, HeaderFlag } from "../../../src/wire/commands.js";

describe("smb2-header", () => {
  it("encodes a SYNC NEGOTIATE request header round-trip", () => {
    const buf = encodeHeader({
      command: SmbCommand.NEGOTIATE,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0,
      messageId: 0n,
      treeId: 0,
      sessionId: 0n,
      status: 0,
    });
    expect(buf.length).toBe(64);
    expect(buf.subarray(0, 4)).toEqual(Buffer.from([0xfe, 0x53, 0x4d, 0x42]));
    const { header, isAsync } = decodeHeader(buf);
    expect(isAsync).toBe(false);
    expect(header.command).toBe(SmbCommand.NEGOTIATE);
    expect(header.messageId).toBe(0n);
  });

  it("encodes/decodes ASYNC headers via flag bit", () => {
    const buf = encodeHeader({
      command: SmbCommand.CHANGE_NOTIFY,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: HeaderFlag.ASYNC_COMMAND,
      messageId: 42n,
      asyncId: 0xdeadbeefn,
      sessionId: 0x1122334455667788n,
      status: 0,
    });
    const { header, isAsync } = decodeHeader(buf);
    expect(isAsync).toBe(true);
    expect(header.asyncId).toBe(0xdeadbeefn);
    expect(header.sessionId).toBe(0x1122334455667788n);
  });

  it("preserves the signature field on encode/decode", () => {
    const sig = Buffer.alloc(16, 0xcc);
    const buf = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: HeaderFlag.SIGNED,
      messageId: 1n,
      treeId: 1,
      sessionId: 1n,
      status: 0,
      signature: sig,
    });
    const { header } = decodeHeader(buf);
    expect(header.signature).toEqual(sig);
  });
});
