import { describe, it, expect } from "vitest";
import { Reader } from "../../../src/wire/buffer.js";

describe("Reader", () => {
  it("reads u8/u16/u32/u64 LE in order", () => {
    const buf = Buffer.from("01" + "0203" + "04050607" + "08090a0b0c0d0e0f", "hex");
    const r = new Reader(buf);
    expect(r.u8()).toBe(0x01);
    expect(r.u16()).toBe(0x0302);
    expect(r.u32()).toBe(0x07060504);
    expect(r.u64()).toBe(0x0f0e0d0c0b0a0908n);
    expect(r.remaining()).toBe(0);
  });

  it("reads bytes and advances", () => {
    const r = new Reader(Buffer.from("aabbccdd", "hex"));
    expect(r.bytes(2)).toEqual(Buffer.from("aabb", "hex"));
    expect(r.offset).toBe(2);
  });

  it("reads UTF-16LE", () => {
    const s = "Hi€";
    const buf = Buffer.from(s, "utf16le");
    const r = new Reader(buf);
    expect(r.utf16(buf.length)).toBe(s);
  });

  it("sub() yields a Reader over a slice without advancing parent", () => {
    const r = new Reader(Buffer.from("00010203", "hex"));
    const s = r.sub(1, 2);
    expect(s.u8()).toBe(0x01);
    expect(s.u8()).toBe(0x02);
    expect(r.offset).toBe(0);
  });

  it("throws on overrun", () => {
    const r = new Reader(Buffer.from("00", "hex"));
    expect(() => r.u16()).toThrow();
  });
});
