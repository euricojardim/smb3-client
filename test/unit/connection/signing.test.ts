import { createCipheriv, randomBytes } from "node:crypto";
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
  it("64-byte message", () => {
    const M = Buffer.from(
      "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
      "hex",
    );
    expect(aesCmac(K, M).toString("hex")).toBe("51f0bebf7e3b9d92fc49741779363cfe");
  });
});

// The RFC 4493 algorithm block by block (one AES-ECB per block) - the reference the one-pass CBC version must match.
function referenceCmac(key: Buffer, msg: Buffer): Buffer {
  const ecb = (b: Buffer) => {
    const c = createCipheriv("aes-128-ecb", key, null);
    c.setAutoPadding(false);
    return Buffer.concat([c.update(b), c.final()]);
  };
  const shift = (b: Buffer) => {
    const out = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) out[i] = ((b[i]! << 1) & 0xff) | (i < 15 ? b[i + 1]! >> 7 : 0);
    return out;
  };
  const L = ecb(Buffer.alloc(16));
  const k1 = shift(L);
  if (L[0]! & 0x80) k1[15] = k1[15]! ^ 0x87;
  const k2 = shift(k1);
  if (k1[0]! & 0x80) k2[15] = k2[15]! ^ 0x87;
  const n = Math.max(1, Math.ceil(msg.length / 16));
  const full = msg.length > 0 && msg.length % 16 === 0;
  const last = Buffer.alloc(16);
  msg.subarray((n - 1) * 16).copy(last);
  if (!full) last[msg.length - (n - 1) * 16] = 0x80;
  for (let i = 0; i < 16; i++) last[i] = last[i]! ^ (full ? k1 : k2)[i]!;
  let x = Buffer.alloc(16);
  for (let b = 0; b < n - 1; b++) {
    const y = Buffer.alloc(16);
    for (let i = 0; i < 16; i++) y[i] = x[i]! ^ msg[b * 16 + i]!;
    x = ecb(y);
  }
  for (let i = 0; i < 16; i++) last[i] = last[i]! ^ x[i]!;
  return ecb(last);
}

describe("aesCmac matches the block-by-block algorithm", () => {
  it("every length from 0 to 100 bytes (empty, partial and full last blocks)", () => {
    const key = randomBytes(16);
    const msg = randomBytes(100);
    for (let n = 0; n <= 100; n++) expect(aesCmac(key, msg.subarray(0, n))).toEqual(referenceCmac(key, msg.subarray(0, n)));
  });
  it("a large message (1 MiB + 7 bytes)", () => {
    const key = randomBytes(16);
    const msg = randomBytes(1024 * 1024 + 7);
    expect(aesCmac(key, msg)).toEqual(referenceCmac(key, msg));
  });
  it("does not change the message", () => {
    const key = randomBytes(16);
    const msg = randomBytes(48);
    const copy = Buffer.from(msg);
    aesCmac(key, msg);
    expect(msg).toEqual(copy);
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
