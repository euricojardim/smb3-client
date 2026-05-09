import { describe, it, expect } from "vitest";
import { aesCmac, hmacSha256, sign, verify } from "../../../src/connection/signing.js";
import { Dialect } from "../../../src/wire/commands.js";

// RFC 4493 test vectors: K = 2b7e151628aed2a6abf7158809cf4f3c
describe("aesCmac (RFC 4493)", () => {
  const K = Buffer.from("2b7e151628aed2a6abf7158809cf4f3c", "hex");
  it("empty message", () => {
    expect(aesCmac(K, Buffer.alloc(0)).toString("hex")).toBe("bb1d6929e95937287fa37d129b756746");
  });
  it("16-byte message", () => {
    const M = Buffer.from("6bc1bee22e409f96e93d7e117393172a", "hex");
    expect(aesCmac(K, M).toString("hex")).toBe("070a16b46b4d4144f79bdd9dd04a287c");
  });
  it("40-byte message", () => {
    const M = Buffer.from(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411",
      "hex",
    );
    expect(aesCmac(K, M).toString("hex")).toBe("dfa66747de9ae63030ca32611497c827");
  });
});

describe("sign(dialect)", () => {
  it("uses HMAC-SHA256 truncated to 16 for SMB 2.1", () => {
    const key = Buffer.alloc(16, 0x11);
    const msg = Buffer.alloc(64, 0xab);
    const sig = sign(msg, key, Dialect.SMB_2_1_0);
    expect(sig.length).toBe(16);
    const full = hmacSha256(key, msg);
    expect(sig).toEqual(full.subarray(0, 16));
  });

  it("uses AES-CMAC for SMB 3.0+", () => {
    const key = Buffer.alloc(16, 0x22);
    const msg = Buffer.alloc(64, 0xcd);
    expect(sign(msg, key, Dialect.SMB_3_0_2)).toEqual(aesCmac(key, msg));
  });

  it("verify accepts a valid signature", () => {
    const key = Buffer.alloc(16, 0x33);
    const msg = Buffer.alloc(64, 0xee);
    const sig = sign(msg, key, Dialect.SMB_3_1_1);
    expect(verify(msg, sig, key, Dialect.SMB_3_1_1)).toBe(true);
    sig[0] ^= 0xff;
    expect(verify(msg, sig, key, Dialect.SMB_3_1_1)).toBe(false);
  });
});
