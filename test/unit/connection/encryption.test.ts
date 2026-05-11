import { describe, it, expect } from "vitest";
import {
  encryptMessage,
  decryptMessage,
  isTransformHeader,
  TRANSFORM_HEADER_SIZE,
  type EncryptionKeys,
} from "../../../src/connection/encryption.js";
import { Cipher } from "../../../src/wire/commands.js";
import { SmbProtocolError } from "../../../src/errors.js";

function keys128(): EncryptionKeys {
  return {
    encryption: Buffer.alloc(16, 0x11),
    decryption: Buffer.alloc(16, 0x22),
    cipherId: Cipher.AES_128_CCM,
  };
}

function keys256(): EncryptionKeys {
  return {
    encryption: Buffer.alloc(32, 0x33),
    decryption: Buffer.alloc(32, 0x44),
    cipherId: Cipher.AES_256_GCM,
  };
}

describe("isTransformHeader", () => {
  it("returns true for 0xFD S M B", () => {
    expect(isTransformHeader(Buffer.from([0xfd, 0x53, 0x4d, 0x42, 0x00]))).toBe(true);
  });
  it("returns false for 0xFE S M B (normal SMB2 PDU)", () => {
    expect(isTransformHeader(Buffer.from([0xfe, 0x53, 0x4d, 0x42, 0x00]))).toBe(false);
  });
  it("returns false for buffers shorter than 4 bytes", () => {
    expect(isTransformHeader(Buffer.alloc(0))).toBe(false);
    expect(isTransformHeader(Buffer.from([0xfd, 0x53, 0x4d]))).toBe(false);
  });
});

describe("encryptMessage layout", () => {
  it("produces a 52-byte transform header followed by ciphertext", () => {
    const plaintext = Buffer.from("hello smb encryption world");
    const out = encryptMessage(plaintext, keys128(), 0xdeadbeefn, 1n);
    expect(out.length).toBe(TRANSFORM_HEADER_SIZE + plaintext.length);
    expect(out.subarray(0, 4)).toEqual(Buffer.from([0xfd, 0x53, 0x4d, 0x42]));
    expect(out.readUInt32LE(36)).toBe(plaintext.length);
    expect(out.readUInt16LE(40)).toBe(0); // Reserved
    expect(out.readUInt16LE(42)).toBe(0x0001); // Flags / EncryptionAlgorithm
    expect(out.readBigUInt64LE(44)).toBe(0xdeadbeefn);
  });

  it("CCM uses 11-byte nonce, zero-padded to 16 in the header", () => {
    const out = encryptMessage(Buffer.from("x"), keys128(), 1n, 0x0123456789abcdefn);
    expect(out.readBigUInt64LE(20)).toBe(0x0123456789abcdefn);
    expect(out.readUInt8(28)).toBe(0); // bytes 28..36 of nonce: first 3 zero per CCM
    expect(out.readUInt8(30)).toBe(0);
    expect(out.readUInt8(31)).toBe(0); // last byte of nonce field also zero
    expect(out.readUInt8(32)).toBe(0); // and zero-padding beyond the 11-byte nonce
    expect(out.readUInt8(35)).toBe(0);
  });

  it("GCM uses 12-byte nonce, zero-padded to 16 in the header", () => {
    const k: EncryptionKeys = {
      encryption: Buffer.alloc(16, 0xaa),
      decryption: Buffer.alloc(16, 0xbb),
      cipherId: Cipher.AES_128_GCM,
    };
    const out = encryptMessage(Buffer.from("x"), k, 2n, 0x0123456789abcdefn);
    expect(out.readBigUInt64LE(20)).toBe(0x0123456789abcdefn);
    expect(out.readUInt32LE(28)).toBe(0); // bytes 28..32 of nonce: zero (counter is in low 8)
    expect(out.readUInt32LE(32)).toBe(0); // zero-padding beyond 12-byte nonce
  });
});

describe("encrypt/decrypt round-trip", () => {
  for (const cid of [
    Cipher.AES_128_CCM,
    Cipher.AES_128_GCM,
    Cipher.AES_256_CCM,
    Cipher.AES_256_GCM,
  ]) {
    const keyLen = cid === Cipher.AES_128_CCM || cid === Cipher.AES_128_GCM ? 16 : 32;
    it(`round-trips with cipher 0x000${cid}`, () => {
      const k: EncryptionKeys = {
        encryption: Buffer.alloc(keyLen, 0x55),
        decryption: Buffer.alloc(keyLen, 0x55), // same key both directions for round-trip
        cipherId: cid,
      };
      const plaintext = Buffer.from("a moderately interesting SMB2 PDU here");
      const wire = encryptMessage(plaintext, k, 0xabcd1234n, 7n);
      const got = decryptMessage(wire, k, 0xabcd1234n);
      expect(got).toEqual(plaintext);
    });
  }

  it("decrypt fails when ciphertext is tampered", () => {
    const k = keys128();
    const kRecv: EncryptionKeys = { ...k, decryption: k.encryption };
    const wire = encryptMessage(Buffer.from("payload bytes"), k, 1n, 1n);
    wire[TRANSFORM_HEADER_SIZE + 2] ^= 0x01;
    expect(() => decryptMessage(wire, kRecv, 1n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails when the AAD (header nonce/sessionId) is tampered", () => {
    const k = keys128();
    const kRecv: EncryptionKeys = { ...k, decryption: k.encryption };
    const wire = encryptMessage(Buffer.from("payload bytes"), k, 1n, 1n);
    wire[20] ^= 0x01; // flip a nonce byte (part of AAD)
    expect(() => decryptMessage(wire, kRecv, 1n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails when the auth tag is tampered", () => {
    const k = keys128();
    const kRecv: EncryptionKeys = { ...k, decryption: k.encryption };
    const wire = encryptMessage(Buffer.from("payload bytes"), k, 1n, 1n);
    wire[4] ^= 0x01;
    expect(() => decryptMessage(wire, kRecv, 1n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails on sessionId mismatch", () => {
    const k = keys128();
    const kRecv: EncryptionKeys = { ...k, decryption: k.encryption };
    const wire = encryptMessage(Buffer.from("payload"), k, 1n, 1n);
    expect(() => decryptMessage(wire, kRecv, 2n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails on wrong key", () => {
    const k = keys128();
    const kRecv: EncryptionKeys = { ...k, decryption: Buffer.alloc(16, 0x99) };
    const wire = encryptMessage(Buffer.from("payload"), k, 1n, 1n);
    expect(() => decryptMessage(wire, kRecv, 1n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails on too-short frame", () => {
    expect(() => decryptMessage(Buffer.alloc(10), keys128(), 1n)).toThrow(SmbProtocolError);
  });

  it("decrypt fails on bad ProtocolId", () => {
    const buf = Buffer.alloc(60);
    buf[0] = 0xfe; // not 0xfd
    expect(() => decryptMessage(buf, keys128(), 1n)).toThrow(SmbProtocolError);
  });

  it("AES-256-CCM round-trips with 32-byte key", () => {
    const k: EncryptionKeys = {
      encryption: Buffer.alloc(32, 0x77),
      decryption: Buffer.alloc(32, 0x77),
      cipherId: Cipher.AES_256_CCM,
    };
    const plaintext = Buffer.from("256-bit CCM SMB payload");
    const wire = encryptMessage(plaintext, k, 9n, 42n);
    expect(decryptMessage(wire, k, 9n)).toEqual(plaintext);
  });
});

describe("nonce uniqueness across counter values", () => {
  it("different counters produce different ciphertexts for the same plaintext", () => {
    const k = keys128();
    const pt = Buffer.from("repeat me");
    const a = encryptMessage(pt, k, 1n, 1n);
    const b = encryptMessage(pt, k, 1n, 2n);
    expect(a.subarray(TRANSFORM_HEADER_SIZE)).not.toEqual(b.subarray(TRANSFORM_HEADER_SIZE));
    expect(a.subarray(20, 36)).not.toEqual(b.subarray(20, 36));
  });
});

describe("256-bit GCM round-trip", () => {
  it("works with 32-byte key", () => {
    const k = keys256();
    const kRecv: EncryptionKeys = { ...k, decryption: k.encryption };
    const pt = Buffer.from("a 256-bit GCM payload");
    const wire = encryptMessage(pt, k, 5n, 5n);
    expect(decryptMessage(wire, kRecv, 5n)).toEqual(pt);
  });
});
