import { describe, it, expect } from "vitest";
import {
  encodeNegotiateMessage,
  decodeChallengeMessage,
  encodeAuthenticateMessage,
  computeNtlmV2,
  NTLMSSP_FLAGS,
} from "../../../src/session/ntlm.js";
import { Writer } from "../../../src/wire/buffer.js";

describe("NTLMSSP NEGOTIATE", () => {
  it("starts with 'NTLMSSP\\0', message type 1, expected flags", () => {
    const buf = encodeNegotiateMessage();
    expect(buf.subarray(0, 8)).toEqual(Buffer.from("NTLMSSP\0"));
    expect(buf.readUInt32LE(8)).toBe(1);
    const flags = buf.readUInt32LE(12);
    expect(flags & NTLMSSP_FLAGS.NEGOTIATE_UNICODE).toBeTruthy();
    expect(flags & NTLMSSP_FLAGS.NEGOTIATE_ALWAYS_SIGN).toBeTruthy();
    expect(flags & NTLMSSP_FLAGS.NEGOTIATE_NTLM).toBeTruthy();
    expect(flags & NTLMSSP_FLAGS.NEGOTIATE_KEY_EXCH).toBeTruthy();
  });
});

describe("NTLMSSP CHALLENGE decode", () => {
  it("extracts ServerChallenge and TargetInfo", () => {
    // Build a synthetic CHALLENGE message
    const w = new Writer();
    w.bytes(Buffer.from("NTLMSSP\0"));
    w.u32(2); // type
    // TargetName fields (len, maxlen, offset)
    w.u16(0); w.u16(0); w.u32(0);
    // Flags
    w.u32(0);
    // ServerChallenge
    const serverChallenge = Buffer.from("0123456789abcdef", "hex");
    w.bytes(serverChallenge);
    // Reserved
    w.bytes(Buffer.alloc(8));
    // TargetInfo fields (len, maxlen, offset)
    const ti = Buffer.from("00000000", "hex"); // EOL AV pair (type 0, len 0)
    const tiOffset = 56;
    w.u16(ti.length); w.u16(ti.length); w.u32(tiOffset);
    // Version (8 bytes)
    w.bytes(Buffer.alloc(8));
    // Payload at offset 56
    w.bytes(ti);
    const buf = w.buffer();
    const r = decodeChallengeMessage(buf);
    expect(r.serverChallenge).toEqual(serverChallenge);
    expect(r.targetInfo).toEqual(ti);
  });
});

describe("computeNtlmV2", () => {
  it("produces 16-byte session base key and an NTProofStr-prefixed response", () => {
    const r = computeNtlmV2({
      password: "Password",
      username: "User",
      domain: "Domain",
      serverChallenge: Buffer.from("0123456789abcdef", "hex"),
      clientChallenge: Buffer.from("aaaaaaaaaaaaaaaa", "hex"),
      targetInfo: Buffer.from("00000000", "hex"),
      time: 0n,
    });
    expect(r.sessionBaseKey.length).toBe(16);
    expect(r.ntChallengeResponse.length).toBeGreaterThanOrEqual(16);
  });
});

describe("NTLMSSP AUTHENTICATE encode", () => {
  it("starts with NTLMSSP\\0 and message type 3", () => {
    const ntResp = Buffer.alloc(24);
    const lmResp = Buffer.alloc(24);
    const sessKey = Buffer.alloc(16);
    const buf = encodeAuthenticateMessage({
      domain: "DOMAIN",
      username: "user",
      ntChallengeResponse: ntResp,
      lmChallengeResponse: lmResp,
      encryptedRandomSessionKey: sessKey,
      flags: NTLMSSP_FLAGS.NEGOTIATE_UNICODE | NTLMSSP_FLAGS.NEGOTIATE_NTLM,
    });
    expect(buf.subarray(0, 8)).toEqual(Buffer.from("NTLMSSP\0"));
    expect(buf.readUInt32LE(8)).toBe(3);
  });
});
