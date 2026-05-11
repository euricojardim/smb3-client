import { Reader, Writer } from "../buffer.js";
import { Dialect, NegotiateContextType } from "../commands.js";

export interface NegotiateRequest {
  dialects: number[];
  clientGuid: Buffer; // 16 bytes
  capabilities: number;
  securityMode: number;
  preauthSalt?: Buffer; // 32 bytes; required if SMB_3_1_1 advertised
  ciphers?: number[];  // SMB 3.1.1 EncryptionCapabilities cipher IDs, in client preference order
}

const STRUCT_SIZE_REQ = 36;

export function encodeNegotiateRequest(req: NegotiateRequest): Buffer {
  if (req.clientGuid.length !== 16) throw new Error("clientGuid must be 16 bytes");
  const has311 = req.dialects.includes(Dialect.SMB_3_1_1);
  if (has311 && (!req.preauthSalt || req.preauthSalt.length !== 32)) {
    throw new Error("preauthSalt (32 bytes) required when SMB 3.1.1 is advertised");
  }
  const w = new Writer();
  w.u16(STRUCT_SIZE_REQ);
  w.u16(req.dialects.length);
  w.u16(req.securityMode);
  w.u16(0); // Reserved
  w.u32(req.capabilities);
  w.bytes(req.clientGuid);

  if (has311) {
    const ciphers = req.ciphers ?? [];
    const ctxCount = 1 + (ciphers.length > 0 ? 1 : 0);

    // NegotiateContextOffset (4) + NegotiateContextCount (2) + Reserved2 (2)
    // Offset is from the SMB2 header start; we're encoding the body, so caller
    // adds 64 (header). We compute it relative to body and patch at the end.
    const ctxOffsetPatchAt = w.offset;
    w.u32(0);
    w.u16(ctxCount);
    w.u16(0); // Reserved2

    // Dialects list (2 * count)
    for (const d of req.dialects) w.u16(d);
    w.padTo(8);

    const bodyCtxStart = w.offset;
    // Body offset to absolute: contexts come after StructureSize..Padding;
    // server expects offset relative to SMB2 header (64).
    const ctxOffsetFromHeader = 64 + bodyCtxStart;
    const buf = w.buffer();
    buf.writeUInt32LE(ctxOffsetFromHeader, ctxOffsetPatchAt);

    const ctx = new Writer();
    // PreauthIntegrity context: type=1, dataLen, reserved, hashAlgCount(1), saltLen, hashAlg(SHA-512=1), salt(32)
    ctx.u16(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES);
    const preauthDataLen = 2 + 2 + 2 + 32; // hashAlgCount + saltLen + hashAlg + salt
    ctx.u16(preauthDataLen);
    ctx.u32(0); // Reserved
    ctx.u16(1); // HashAlgorithmCount
    ctx.u16(32); // SaltLength
    ctx.u16(1); // SHA-512
    ctx.bytes(req.preauthSalt!);
    if (ciphers.length > 0) {
      ctx.padTo(8);
      // EncryptionCapabilities context: type=2, dataLen, reserved, cipherCount, ciphers[]
      ctx.u16(NegotiateContextType.ENCRYPTION_CAPABILITIES);
      const encDataLen = 2 + 2 * ciphers.length;
      ctx.u16(encDataLen);
      ctx.u32(0); // Reserved
      ctx.u16(ciphers.length);
      for (const c of ciphers) ctx.u16(c);
    }
    ctx.padTo(8);

    return Buffer.concat([buf, ctx.buffer()]);
  }

  // Pre-3.1.1 layout: ClientStartTime (8 bytes, set to 0)
  w.u64(0n);
  for (const d of req.dialects) w.u16(d);
  return w.buffer();
}

export interface NegotiateResponse {
  dialect: number;
  securityMode: number;
  serverGuid: Buffer;
  capabilities: number;
  maxTransactSize: number;
  maxReadSize: number;
  maxWriteSize: number;
  systemTime: bigint;
  serverStartTime: bigint;
  securityBuffer: Buffer;
  preauthHashAlg?: number;
  preauthSalt?: Buffer;
  cipherIds?: number[];
}

const STRUCT_SIZE_RESP = 65;

/**
 * Decode a NEGOTIATE response body. `bodyAt` is the absolute byte offset of
 * `body[0]` within the original SMB2 message — needed because context and
 * security-buffer offsets in the response are relative to the SMB2 header
 * start (i.e. include the 64 header bytes that this body buffer omits).
 */
export function decodeNegotiateResponse(body: Buffer, bodyAt = 64): NegotiateResponse {
  const r = new Reader(body);
  const structureSize = r.u16();
  if (structureSize !== STRUCT_SIZE_RESP) {
    throw new Error(`NEGOTIATE response StructureSize ${structureSize} != 65`);
  }
  const securityMode = r.u16();
  const dialect = r.u16();
  const negotiateContextCount = r.u16();
  const serverGuid = r.bytes(16);
  const capabilities = r.u32();
  const maxTransactSize = r.u32();
  const maxReadSize = r.u32();
  const maxWriteSize = r.u32();
  const systemTime = r.u64();
  const serverStartTime = r.u64();
  const securityBufferOffset = r.u16();
  const securityBufferLength = r.u16();
  const negotiateContextOffsetField = r.u32();

  let securityBuffer = Buffer.alloc(0);
  if (securityBufferLength > 0) {
    const start = securityBufferOffset - bodyAt;
    securityBuffer = Buffer.from(body.subarray(start, start + securityBufferLength));
  }

  const out: NegotiateResponse = {
    dialect,
    securityMode,
    serverGuid,
    capabilities,
    maxTransactSize,
    maxReadSize,
    maxWriteSize,
    systemTime,
    serverStartTime,
    securityBuffer,
  };

  if (dialect === Dialect.SMB_3_1_1 && negotiateContextCount > 0) {
    let cursor = negotiateContextOffsetField - bodyAt;
    out.cipherIds = [];
    for (let i = 0; i < negotiateContextCount; i++) {
      const ctxR = new Reader(body);
      ctxR.offset = cursor;
      const ctxType = ctxR.u16();
      const dataLen = ctxR.u16();
      ctxR.u32(); // Reserved
      const dataStart = ctxR.offset;
      if (ctxType === NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES) {
        const hashAlgCount = ctxR.u16();
        const saltLen = ctxR.u16();
        if (hashAlgCount >= 1) out.preauthHashAlg = ctxR.u16();
        for (let j = 1; j < hashAlgCount; j++) ctxR.u16();
        out.preauthSalt = ctxR.bytes(saltLen);
      } else if (ctxType === NegotiateContextType.ENCRYPTION_CAPABILITIES) {
        const cipherCount = ctxR.u16();
        for (let j = 0; j < cipherCount; j++) out.cipherIds!.push(ctxR.u16());
      }
      // Advance cursor past data + 8-byte alignment
      const next = dataStart + dataLen;
      cursor = (next + 7) & ~7;
    }
  }

  return out;
}
