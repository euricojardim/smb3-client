import { describe, it, expect } from "vitest";
import {
  encodeSessionSetupRequest,
  decodeSessionSetupResponse,
} from "../../../../src/wire/structs/sessionSetup.js";
import { Writer } from "../../../../src/wire/buffer.js";

describe("SESSION_SETUP", () => {
  it("encodes structure size 25 and embeds the security blob", () => {
    const blob = Buffer.from("aabbccdd", "hex");
    const buf = encodeSessionSetupRequest({ securityMode: 1, capabilities: 0, blob });
    expect(buf.readUInt16LE(0)).toBe(25);
    const off = buf.readUInt16LE(12);
    const len = buf.readUInt16LE(14);
    expect(buf.subarray(off - 64, off - 64 + len).equals(blob)).toBe(true);
  });

  it("decodes a synthetic response", () => {
    const blob = Buffer.from("eeff", "hex");
    const w = new Writer();
    w.u16(9); // StructureSize
    w.u16(0); // SessionFlags
    w.u16(64 + 8); // SecurityBufferOffset
    w.u16(blob.length); // SecurityBufferLength
    w.bytes(blob);
    const r = decodeSessionSetupResponse(w.buffer(), 64);
    expect(r.sessionFlags).toBe(0);
    expect(r.securityBuffer).toEqual(blob);
  });
});
