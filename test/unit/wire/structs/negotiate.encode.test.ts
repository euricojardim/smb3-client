import { describe, it, expect } from "vitest";
import { encodeNegotiateRequest } from "../../../../src/wire/structs/negotiate.js";
import { Dialect, SecurityMode, Capability } from "../../../../src/wire/commands.js";

describe("encodeNegotiateRequest", () => {
  it("encodes structure size 36 and dialect count", () => {
    const buf = encodeNegotiateRequest({
      dialects: [Dialect.SMB_2_1_0, Dialect.SMB_3_0_0, Dialect.SMB_3_0_2, Dialect.SMB_3_1_1],
      clientGuid: Buffer.alloc(16, 0xaa),
      capabilities: Capability.LARGE_MTU,
      securityMode: SecurityMode.SIGNING_ENABLED,
      preauthSalt: Buffer.alloc(32, 0xbb),
    });
    expect(buf.readUInt16LE(0)).toBe(36);
    expect(buf.readUInt16LE(2)).toBe(4); // DialectCount
    expect(buf.readUInt16LE(4)).toBe(SecurityMode.SIGNING_ENABLED);
    expect(buf.readUInt32LE(8)).toBe(Capability.LARGE_MTU);
  });

  it("includes preauth integrity context when 3.1.1 in dialects", () => {
    const buf = encodeNegotiateRequest({
      dialects: [Dialect.SMB_3_1_1],
      clientGuid: Buffer.alloc(16, 0),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
      preauthSalt: Buffer.alloc(32, 0xcc),
    });
    // NegotiateContextOffset and Count present at offset 28..32, 32..34
    const ctxOffset = buf.readUInt32LE(28);
    const ctxCount = buf.readUInt16LE(32);
    expect(ctxCount).toBeGreaterThanOrEqual(2); // preauth + encryption (we advertise no ciphers)
    expect(ctxOffset).toBeGreaterThanOrEqual(36);
  });

  it("omits preauth context when 3.1.1 not advertised", () => {
    const buf = encodeNegotiateRequest({
      dialects: [Dialect.SMB_2_1_0],
      clientGuid: Buffer.alloc(16, 0),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
    });
    expect(buf.readUInt32LE(28)).toBe(0); // ClientStartTime field, not context offset
  });
});
