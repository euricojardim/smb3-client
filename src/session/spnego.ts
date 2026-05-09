// Tiny ASN.1 DER helpers — only what SPNEGO with NTLMSSP needs.
// We never parse arbitrary ASN.1 — we accept tokens that match our limited shape.

const NTLMSSP_OID = Buffer.from("2b06010401823702020a", "hex"); // 1.3.6.1.4.1.311.2.2.10
const SPNEGO_OID = Buffer.from("2b0601050502", "hex"); // 1.3.6.1.5.5.2

function derLen(n: number): Buffer {
  if (n < 0x80) return Buffer.from([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function tlv(tag: number, value: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(value.length), value]);
}

function readLen(buf: Buffer, off: number): { len: number; off: number } {
  const first = buf[off++]!;
  if (first < 0x80) return { len: first, off };
  const numBytes = first & 0x7f;
  let len = 0;
  for (let i = 0; i < numBytes; i++) len = (len << 8) | buf[off++]!;
  return { len, off };
}

export function wrapInitNegToken(ntlmToken: Buffer): Buffer {
  // NegTokenInit ::= [0] EXPLICIT SEQUENCE { mechTypes [0] SEQUENCE OF OID, mechToken [2] OCTET STRING }
  const oidTlv = tlv(0x06, NTLMSSP_OID);
  const mechTypeList = tlv(0x30, oidTlv); // SEQUENCE OF OID
  const mechTypes = tlv(0xa0, mechTypeList); // [0]
  const mechToken = tlv(0xa2, tlv(0x04, ntlmToken)); // [2] OCTET STRING
  const negTokenInit = tlv(0x30, Buffer.concat([mechTypes, mechToken]));
  const negTokenTagged = tlv(0xa0, negTokenInit); // [0] EXPLICIT
  // GSS-API: [APPLICATION 0] IMPLICIT SEQUENCE { thisMech OID, innerContextToken ANY }
  const inner = Buffer.concat([tlv(0x06, SPNEGO_OID), negTokenTagged]);
  return tlv(0x60, inner);
}

export function wrapNegTokenResp(ntlmToken: Buffer): Buffer {
  // NegTokenResp ::= [1] EXPLICIT SEQUENCE { responseToken [2] OCTET STRING }
  const responseToken = tlv(0xa2, tlv(0x04, ntlmToken));
  const negTokenResp = tlv(0x30, responseToken);
  return tlv(0xa1, negTokenResp);
}

export function extractNtlmFromResp(spnego: Buffer): Buffer {
  let off = 0;
  if (spnego[off] === 0xa1) {
    off++;
    ({ off } = readLen(spnego, off));
    if (spnego[off++] !== 0x30) throw new Error("SPNEGO: expected SEQUENCE");
    ({ off } = readLen(spnego, off));
    while (off < spnego.length) {
      const tag = spnego[off++]!;
      const { len, off: o } = readLen(spnego, off);
      off = o;
      if (tag === 0xa2) {
        if (spnego[off++] !== 0x04) throw new Error("SPNEGO: expected OCTET STRING");
        const { len: l, off: o2 } = readLen(spnego, off);
        return Buffer.from(spnego.subarray(o2, o2 + l));
      }
      off += len;
    }
  }
  throw new Error("SPNEGO: no responseToken found");
}

export function extractNtlmFromInit(spnego: Buffer): Buffer {
  // Used to parse the server's NegTokenInit-2 in the negotiate response (if any).
  // Returns either the inner NTLMSSP blob or an empty buffer if none.
  if (spnego[0] !== 0x60) return Buffer.alloc(0);
  let off = 1;
  ({ off } = readLen(spnego, off));
  // Skip OID
  if (spnego[off++] !== 0x06) return Buffer.alloc(0);
  const { len: oidLen, off: oOff } = readLen(spnego, off);
  off = oOff + oidLen;
  // [0] EXPLICIT NegTokenInit
  if (spnego[off++] !== 0xa0) return Buffer.alloc(0);
  ({ off } = readLen(spnego, off));
  if (spnego[off++] !== 0x30) return Buffer.alloc(0);
  ({ off } = readLen(spnego, off));
  while (off < spnego.length) {
    const tag = spnego[off++]!;
    const { len, off: o } = readLen(spnego, off);
    off = o;
    if (tag === 0xa2) {
      if (spnego[off++] !== 0x04) return Buffer.alloc(0);
      const { len: l, off: o2 } = readLen(spnego, off);
      return Buffer.from(spnego.subarray(o2, o2 + l));
    }
    off += len;
  }
  return Buffer.alloc(0);
}
