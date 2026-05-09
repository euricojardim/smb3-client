import { describe, it, expect } from "vitest";
import { decodeNegotiateResponse } from "../../../../src/wire/structs/negotiate.js";
import { Writer } from "../../../../src/wire/buffer.js";
import { Dialect, NegotiateContextType } from "../../../../src/wire/commands.js";

function buildSyntheticResponse(): Buffer {
  // Body only (caller strips the SMB2 header).
  const w = new Writer();
  w.u16(65); // StructureSize
  w.u16(1); // SecurityMode (signing enabled)
  w.u16(Dialect.SMB_3_1_1);
  w.u16(2); // NegotiateContextCount
  w.bytes(Buffer.alloc(16, 0xee)); // ServerGuid
  w.u32(0); // Capabilities
  w.u32(8 * 1024 * 1024); // MaxTransactSize
  w.u32(8 * 1024 * 1024); // MaxReadSize
  w.u32(8 * 1024 * 1024); // MaxWriteSize
  w.u64(0n); // SystemTime
  w.u64(0n); // ServerStartTime
  w.u16(64 + 64); // SecurityBufferOffset (header + body up to here-ish; we'll patch)
  w.u16(0); // SecurityBufferLength = 0
  // Patch security offset later if needed; for now hardcode body start (64) + 64 (header offset).
  // NegotiateContextOffset patched after we know contexts location.
  const ctxOffsetPatchAt = w.offset;
  w.u32(0);
  // No security buffer
  // Pad to 8
  w.padTo(8);
  const ctxStartFromBody = w.offset;
  // Patch context offset = 64 (header) + ctxStartFromBody
  // (test doesn't include the header itself, so the decoder must accept body-relative offsets;
  // the real codec accepts absolute-from-header offsets. We re-decode by passing bodyAt=64.)
  // Append two contexts.
  // Preauth
  w.u16(NegotiateContextType.PREAUTH_INTEGRITY_CAPABILITIES);
  w.u16(2 + 2 + 2 + 32);
  w.u32(0);
  w.u16(1);
  w.u16(32);
  w.u16(1); // SHA-512
  w.bytes(Buffer.alloc(32, 0x77));
  w.padTo(8);
  // Encryption (server picked nothing, but include zero-cipher to keep parser exercised)
  w.u16(NegotiateContextType.ENCRYPTION_CAPABILITIES);
  w.u16(2);
  w.u32(0);
  w.u16(0);
  w.padTo(8);
  const buf = w.buffer();
  buf.writeUInt32LE(64 + ctxStartFromBody, ctxOffsetPatchAt);
  return buf;
}

describe("decodeNegotiateResponse", () => {
  it("decodes a synthetic 3.1.1 response", () => {
    const body = buildSyntheticResponse();
    const r = decodeNegotiateResponse(body, 64);
    expect(r.dialect).toBe(Dialect.SMB_3_1_1);
    expect(r.maxReadSize).toBe(8 * 1024 * 1024);
    expect(r.preauthHashAlg).toBe(1);
    expect(r.preauthSalt?.length).toBe(32);
    expect(r.cipherIds).toEqual([]);
    expect(r.serverGuid.length).toBe(16);
  });
});
