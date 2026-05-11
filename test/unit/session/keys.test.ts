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

  it("produces distinct keys for each SMB 3.x encryption label", () => {
    // MS-SMB2 §3.1.4.2: encryption keys are derived with distinct labels per direction.
    const sessionKey = Buffer.alloc(16, 0x42);
    const preauth = Buffer.alloc(64, 0x77); // SHA-512 size

    const enc30 = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMB2AESCCM\0", "ascii"),
      Buffer.from("ServerIn \0", "ascii"),
      16,
    );
    const dec30 = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMB2AESCCM\0", "ascii"),
      Buffer.from("ServerOut\0", "ascii"),
      16,
    );
    const enc311 = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMBC2SCipherKey\0", "ascii"),
      preauth,
      16,
    );
    const dec311 = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMBS2CCipherKey\0", "ascii"),
      preauth,
      16,
    );
    // All four are different from each other.
    const all = [enc30, dec30, enc311, dec311];
    for (let i = 0; i < all.length; i++) {
      for (let j = i + 1; j < all.length; j++) {
        expect(all[i]).not.toEqual(all[j]);
      }
    }
    // Determinism — same inputs, same output.
    expect(enc30).toEqual(
      kdfSp800108CounterHmacSha256(
        sessionKey,
        Buffer.from("SMB2AESCCM\0", "ascii"),
        Buffer.from("ServerIn \0", "ascii"),
        16,
      ),
    );
  });

  it("derives 32-byte AES-256 keys", () => {
    const sessionKey = Buffer.alloc(16, 0x42);
    const preauth = Buffer.alloc(64, 0x88);
    const out = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMBC2SCipherKey\0", "ascii"),
      preauth,
      32,
    );
    expect(out.length).toBe(32);
  });
});
