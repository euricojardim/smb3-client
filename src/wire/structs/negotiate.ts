import { Writer } from "../buffer.js";
import { Dialect, NegotiateContextType } from "../commands.js";

export interface NegotiateRequest {
  dialects: number[];
  clientGuid: Buffer; // 16 bytes
  capabilities: number;
  securityMode: number;
  preauthSalt?: Buffer; // 32 bytes; required if SMB_3_1_1 advertised
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
    // NegotiateContextOffset (4) + NegotiateContextCount (2) + Reserved2 (2)
    // Offset is from the SMB2 header start; we're encoding the body, so caller
    // adds 64 (header). We compute it relative to body and patch at the end.
    const ctxOffsetPatchAt = w.offset;
    w.u32(0);
    w.u16(2); // contexts: preauth + encryption(none)
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

    // Continue appending contexts
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
    ctx.padTo(8);

    // EncryptionCapabilities context: advertise zero ciphers (we don't support encryption)
    ctx.u16(NegotiateContextType.ENCRYPTION_CAPABILITIES);
    ctx.u16(2); // DataLength: just CipherCount(2)
    ctx.u32(0); // Reserved
    ctx.u16(0); // CipherCount = 0
    ctx.padTo(8);

    return Buffer.concat([buf, ctx.buffer()]);
  }

  // Pre-3.1.1 layout: ClientStartTime (8 bytes, set to 0)
  w.u64(0n);
  for (const d of req.dialects) w.u16(d);
  return w.buffer();
}
