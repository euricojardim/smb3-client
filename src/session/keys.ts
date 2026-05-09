import { createHmac } from "node:crypto";

function md4(buf: Buffer): Buffer {
  // node:crypto on most builds doesn't include "md4" any more. Implement RFC 1320 directly.
  // Tiny, dedicated, only used for NTLM password key derivation.
  const F = (x: number, y: number, z: number) => (x & y) | (~x & z);
  const G = (x: number, y: number, z: number) => (x & y) | (x & z) | (y & z);
  const H = (x: number, y: number, z: number) => x ^ y ^ z;
  const ROL = (x: number, n: number) => ((x << n) | (x >>> (32 - n))) >>> 0;

  const lenBits = BigInt(buf.length) * 8n;
  const padLen = ((56 - ((buf.length + 1) % 64) + 64) % 64);
  const total = buf.length + 1 + padLen + 8;
  const m = Buffer.alloc(total);
  buf.copy(m, 0);
  m[buf.length] = 0x80;
  m.writeBigUInt64LE(lenBits, total - 8);

  let a = 0x67452301 >>> 0;
  let b = 0xefcdab89 >>> 0;
  let c = 0x98badcfe >>> 0;
  let d = 0x10325476 >>> 0;

  for (let i = 0; i < total; i += 64) {
    const X: number[] = [];
    for (let j = 0; j < 16; j++) X.push(m.readUInt32LE(i + j * 4));
    const aa = a, bb = b, cc = c, dd = d;
    // RFC 1320: compute new register value first, then rotate (A,B,C,D)->(D,A,B,C)
    const r1 = [3, 7, 11, 19];
    for (let j = 0; j < 16; j++) {
      const k = j;
      const s = r1[j % 4]!;
      a = ROL((a + F(b, c, d) + X[k]!) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }
    const r2 = [3, 5, 9, 13];
    const o2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
    for (let j = 0; j < 16; j++) {
      const k = o2[j]!;
      const s = r2[j % 4]!;
      a = ROL((a + G(b, c, d) + X[k]! + 0x5a827999) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }
    const r3 = [3, 9, 11, 15];
    const o3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
    for (let j = 0; j < 16; j++) {
      const k = o3[j]!;
      const s = r3[j % 4]!;
      a = ROL((a + H(b, c, d) + X[k]! + 0x6ed9eba1) >>> 0, s);
      [a, b, c, d] = [d, a, b, c];
    }
    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0);
  out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8);
  out.writeUInt32LE(d, 12);
  return out;
}

export function hmacMd5(key: Buffer, data: Buffer): Buffer {
  return createHmac("md5", key).update(data).digest();
}

export function ntowfV2(password: string, username: string, domain: string): Buffer {
  const ntPasswordHash = md4(Buffer.from(password, "utf16le"));
  const id = Buffer.from(username.toUpperCase() + domain, "utf16le");
  return hmacMd5(ntPasswordHash, id);
}

/**
 * NIST SP800-108 Counter-mode KDF using HMAC-SHA256.
 * KI is the input key; Label and Context are byte strings.
 * Returns L bytes.
 */
export function kdfSp800108CounterHmacSha256(
  ki: Buffer,
  label: Buffer,
  context: Buffer,
  outBytes: number,
): Buffer {
  const lBits = outBytes * 8;
  const out: Buffer[] = [];
  let produced = 0;
  let counter = 1;
  while (produced < outBytes) {
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter, 0);
    const sep = Buffer.from([0x00]);
    const lEnc = Buffer.alloc(4);
    lEnc.writeUInt32BE(lBits, 0);
    const block = createHmac("sha256", ki)
      .update(c)
      .update(label)
      .update(sep)
      .update(context)
      .update(lEnc)
      .digest();
    out.push(block);
    produced += block.length;
    counter++;
  }
  return Buffer.concat(out, outBytes);
}
