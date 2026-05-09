import { describe, it, expect } from "vitest";
import { frame, FrameReader } from "../../../src/transport/framer.js";

describe("framer", () => {
  it("prepends 4-byte length header (zero + 24-bit BE)", () => {
    const out = frame(Buffer.from("aabbcc", "hex"));
    expect(out).toEqual(Buffer.from("00000003" + "aabbcc", "hex"));
  });

  it("rejects payloads larger than 16 MiB", () => {
    expect(() => frame(Buffer.alloc(0x1_00_00_01))).toThrow();
  });

  it("FrameReader emits whole frames as bytes are fed", () => {
    const r = new FrameReader();
    const f1 = frame(Buffer.from("11", "hex"));
    const f2 = frame(Buffer.from("2233", "hex"));
    const all = Buffer.concat([f1, f2]);
    // Feed in two arbitrary chunks
    r.feed(all.subarray(0, 3));
    expect(r.next()).toBeNull();
    r.feed(all.subarray(3));
    expect(r.next()).toEqual(Buffer.from("11", "hex"));
    expect(r.next()).toEqual(Buffer.from("2233", "hex"));
    expect(r.next()).toBeNull();
  });

  it("FrameReader handles a frame split across many chunks", () => {
    const r = new FrameReader();
    const f = frame(Buffer.alloc(1000, 0x42));
    for (const chunk of [f.subarray(0, 1), f.subarray(1, 5), f.subarray(5, 500), f.subarray(500)]) {
      r.feed(chunk);
    }
    const got = r.next();
    expect(got?.length).toBe(1000);
  });
});
