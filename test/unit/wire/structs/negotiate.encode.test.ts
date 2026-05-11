import { describe, it, expect } from "vitest";
import { encodeNegotiateRequest } from "../../../../src/wire/structs/negotiate.js";
import { Dialect, SecurityMode, Capability, Cipher, NegotiateContextType } from "../../../../src/wire/commands.js";

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

  it("includes only preauth integrity context (no EncryptionCapabilities) when 3.1.1 in dialects", () => {
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
    expect(ctxCount).toBe(1); // preauth only — no EncryptionCapabilities with zero ciphers
    expect(ctxOffset).toBeGreaterThanOrEqual(36);

    // Verify the single context is PreauthIntegrity
    const ctxBodyOffset = ctxOffset - 64; // body-relative offset
    const ctxType = buf.readUInt16LE(ctxBodyOffset);
    expect(ctxType).toBe(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES);
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

  it("includes EncryptionCapabilities context when ciphers are passed and 3.1.1 is advertised", () => {
    const ciphers = [Cipher.AES_128_GCM, Cipher.AES_128_CCM, Cipher.AES_256_GCM, Cipher.AES_256_CCM];
    const buf = encodeNegotiateRequest({
      dialects: [Dialect.SMB_3_1_1],
      clientGuid: Buffer.alloc(16, 0),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
      preauthSalt: Buffer.alloc(32, 0xcc),
      ciphers,
    });
    const ctxOffset = buf.readUInt32LE(28);
    const ctxCount = buf.readUInt16LE(32);
    expect(ctxCount).toBe(2);

    // First context is preauth.
    const firstCtxBodyOffset = ctxOffset - 64;
    expect(buf.readUInt16LE(firstCtxBodyOffset)).toBe(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES);
    const firstDataLen = buf.readUInt16LE(firstCtxBodyOffset + 2);

    // Second context (EncryptionCapabilities) follows at 8-byte alignment.
    const secondHdrStart = firstCtxBodyOffset + 8 + firstDataLen;
    const aligned = (secondHdrStart + 7) & ~7;
    expect(buf.readUInt16LE(aligned)).toBe(NegotiateContextType.ENCRYPTION_CAPABILITIES);
    const encDataLen = buf.readUInt16LE(aligned + 2);
    expect(encDataLen).toBe(2 + 2 * ciphers.length);

    // CipherCount + cipher list in advertised order.
    const dataStart = aligned + 8;
    expect(buf.readUInt16LE(dataStart)).toBe(ciphers.length);
    for (let i = 0; i < ciphers.length; i++) {
      expect(buf.readUInt16LE(dataStart + 2 + 2 * i)).toBe(ciphers[i]);
    }
  });

  it("omits EncryptionCapabilities when ciphers list is empty", () => {
    const buf = encodeNegotiateRequest({
      dialects: [Dialect.SMB_3_1_1],
      clientGuid: Buffer.alloc(16, 0),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED,
      preauthSalt: Buffer.alloc(32, 0xcc),
      ciphers: [],
    });
    expect(buf.readUInt16LE(32)).toBe(1); // preauth only
  });
});
