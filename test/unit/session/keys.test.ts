import { describe, it, expect } from "vitest";
import { ntowfV2, hmacMd5, kdfSp800108CounterHmacSha256 } from "../../../src/session/keys.js";

describe("ntowfV2", () => {
  it("matches HMAC-MD5(MD4(UTF-16LE(password)), UPPER(user) || domain)", () => {
    // Vector from MS-NLMP §4.2.4.1.1: password "Password", user "User", domain "Domain"
    const k = ntowfV2("Password", "User", "Domain");
    expect(k.toString("hex")).toBe("0c868a403bfd7a93a3001ef22ef02e3f");
  });
});

describe("hmacMd5", () => {
  it("matches a known vector", () => {
    const key = Buffer.from("0c868a403bfd7a93a3001ef22ef02e3f", "hex");
    const data = Buffer.from("0123456789abcdef", "hex");
    const out = hmacMd5(key, data);
    expect(out.length).toBe(16);
  });
});

describe("kdfSp800108CounterHmacSha256", () => {
  it("derives 16 bytes deterministically", () => {
    const key = Buffer.alloc(16, 0x42);
    const out = kdfSp800108CounterHmacSha256(key, Buffer.from("LABEL\0", "ascii"), Buffer.from("CONTEXT\0", "ascii"), 16);
    expect(out.length).toBe(16);
    const out2 = kdfSp800108CounterHmacSha256(key, Buffer.from("LABEL\0", "ascii"), Buffer.from("CONTEXT\0", "ascii"), 16);
    expect(out).toEqual(out2);
  });
});
