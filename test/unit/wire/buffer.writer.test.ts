import { describe, it, expect } from "vitest";
import { Writer, Reader } from "../../../src/wire/buffer.js";

describe("Writer", () => {
  it("writes u8/u16/u32/u64 LE", () => {
    const w = new Writer();
    w.u8(0x01);
    w.u16(0x0302);
    w.u32(0x07060504);
    w.u64(0x0f0e0d0c0b0a0908n);
    expect(w.buffer().toString("hex")).toBe("01" + "0203" + "04050607" + "08090a0b0c0d0e0f");
  });

  it("appends bytes and UTF-16LE strings", () => {
    const w = new Writer();
    w.bytes(Buffer.from("aabb", "hex"));
    w.utf16("AB");
    expect(w.buffer().toString("hex")).toBe("aabb" + "41004200");
  });

  it("pads with zeros", () => {
    const w = new Writer();
    w.u8(0xff);
    w.padTo(4);
    expect(w.buffer()).toEqual(Buffer.from("ff000000", "hex"));
  });

  it("round-trips with Reader", () => {
    const w = new Writer();
    w.u32(0xdeadbeef);
    const r = new Reader(w.buffer());
    expect(r.u32()).toBe(0xdeadbeef);
  });
});
