import { createCipheriv, createHmac, timingSafeEqual } from "node:crypto";
import { Dialect } from "../wire/commands.js";

// AES-CMAC (RFC 4493) is CBC-MAC with a tweaked last block. CBC with a zero IV over the
// first n-1 blocks gives the same chaining value as encrypting block by block, so one
// aes-128-cbc cipher does the whole message instead of one cipher object per 16 bytes.
const ZERO_IV = Buffer.alloc(16);

export function hmacSha256(key: Buffer, data: Buffer): Buffer {
  return createHmac("sha256", key).update(data).digest();
}

function cbcEncrypt(key: Buffer, data: Buffer): Buffer {
  const c = createCipheriv("aes-128-cbc", key, ZERO_IV);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(data), c.final()]);
}

function leftShift(b: Buffer): Buffer {
  const out = Buffer.alloc(b.length);
  let carry: number = 0;
  for (let i = b.length - 1; i >= 0; i--) {
    const v = b[i]!;
    out[i] = ((v << 1) & 0xff) | carry;
    carry = (v & 0x80) !== 0 ? 1 : 0;
  }
  return out;
}

function deriveSubkeys(key: Buffer): { k1: Buffer; k2: Buffer } {
  // one block with a zero IV is AES-ECB of the zero block
  const L = cbcEncrypt(key, Buffer.alloc(16));
  const k1 = leftShift(L);
  if (L[0]! & 0x80) k1[15] = k1[15]! ^ 0x87;
  const k2 = leftShift(k1);
  if (k1[0]! & 0x80) k2[15] = k2[15]! ^ 0x87;
  return { k1, k2 };
}

export function aesCmac(key: Buffer, msg: Buffer): Buffer {
  if (key.length !== 16) throw new Error("AES-CMAC: 16-byte key required");
  const { k1, k2 } = deriveSubkeys(key);
  const nBlocks = Math.max(1, Math.ceil(msg.length / 16));
  const lastFull = msg.length > 0 && msg.length % 16 === 0;
  const start = (nBlocks - 1) * 16;

  const lastBlock = Buffer.alloc(16);
  msg.subarray(start).copy(lastBlock, 0);
  if (!lastFull) lastBlock[msg.length - start] = 0x80;
  const k = lastFull ? k1 : k2;
  for (let i = 0; i < 16; i++) lastBlock[i] = lastBlock[i]! ^ k[i]!;

  // CBC over the first n-1 blocks, then the tweaked last block; the MAC is the last cipher block
  const c = createCipheriv("aes-128-cbc", key, ZERO_IV);
  c.setAutoPadding(false);
  c.update(msg.subarray(0, start));
  const out = Buffer.concat([c.update(lastBlock), c.final()]);
  return out.subarray(out.length - 16);
}

export function sign(msg: Buffer, key: Buffer, dialect: number): Buffer {
  if (dialect === Dialect.SMB_2_0_2 || dialect === Dialect.SMB_2_1_0) {
    return hmacSha256(key, msg).subarray(0, 16);
  }
  return aesCmac(key, msg);
}

export function verify(msg: Buffer, sig: Buffer, key: Buffer, dialect: number): boolean {
  const expected = sign(msg, key, dialect);
  if (sig.length !== expected.length) return false;
  return timingSafeEqual(sig, expected);
}
