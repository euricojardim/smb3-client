import { createCipheriv, createDecipheriv } from "node:crypto";
import { Cipher } from "../wire/commands.js";
import { SmbProtocolError } from "../errors.js";

const TRANSFORM_PROTOCOL_ID = Buffer.from([0xfd, 0x53, 0x4d, 0x42]);
export const TRANSFORM_HEADER_SIZE = 52;
const AUTH_TAG_LEN = 16;
const ENCRYPTED_FLAG = 0x0001;

export interface EncryptionKeys {
  encryption: Buffer;
  decryption: Buffer;
  cipherId: number;
}

export interface Encryptor {
  encrypt(plaintext: Buffer): Buffer;
  decrypt(transformFrame: Buffer): Buffer;
}

export function isTransformHeader(buf: Buffer): boolean {
  if (buf.length < 4) return false;
  return buf[0] === 0xfd && buf[1] === 0x53 && buf[2] === 0x4d && buf[3] === 0x42;
}

function isCcm(cipherId: number): boolean {
  return cipherId === Cipher.AES_128_CCM || cipherId === Cipher.AES_256_CCM;
}

function nonceLength(cipherId: number): number {
  return isCcm(cipherId) ? 11 : 12;
}

function counterNonce(counter: bigint, cipherId: number): Buffer {
  const nlen = nonceLength(cipherId);
  const nonce = Buffer.alloc(nlen);
  // Low 8 bytes hold the monotonic counter little-endian; remaining bytes are zero.
  nonce.writeBigUInt64LE(counter, 0);
  return nonce;
}

function aeadEncrypt(
  cipherId: number,
  key: Buffer,
  nonce: Buffer,
  aad: Buffer,
  plaintext: Buffer,
): { ciphertext: Buffer; tag: Buffer } {
  if (cipherId === Cipher.AES_128_CCM || cipherId === Cipher.AES_256_CCM) {
    const alg = cipherId === Cipher.AES_128_CCM ? "aes-128-ccm" : "aes-256-ccm";
    const c = createCipheriv(alg, key, nonce, { authTagLength: AUTH_TAG_LEN });
    c.setAAD(aad, { plaintextLength: plaintext.length });
    const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
    return { ciphertext, tag: c.getAuthTag() };
  }
  if (cipherId === Cipher.AES_128_GCM || cipherId === Cipher.AES_256_GCM) {
    const alg = cipherId === Cipher.AES_128_GCM ? "aes-128-gcm" : "aes-256-gcm";
    const c = createCipheriv(alg, key, nonce, { authTagLength: AUTH_TAG_LEN });
    c.setAAD(aad);
    const ciphertext = Buffer.concat([c.update(plaintext), c.final()]);
    return { ciphertext, tag: c.getAuthTag() };
  }
  throw new SmbProtocolError({ status: 0, message: `unsupported cipher 0x${cipherId.toString(16)}` });
}

function aeadDecrypt(
  cipherId: number,
  key: Buffer,
  nonce: Buffer,
  aad: Buffer,
  ciphertext: Buffer,
  tag: Buffer,
): Buffer {
  if (cipherId === Cipher.AES_128_CCM || cipherId === Cipher.AES_256_CCM) {
    const alg = cipherId === Cipher.AES_128_CCM ? "aes-128-ccm" : "aes-256-ccm";
    const d = createDecipheriv(alg, key, nonce, { authTagLength: AUTH_TAG_LEN });
    d.setAuthTag(tag);
    d.setAAD(aad, { plaintextLength: ciphertext.length });
    return Buffer.concat([d.update(ciphertext), d.final()]);
  }
  if (cipherId === Cipher.AES_128_GCM || cipherId === Cipher.AES_256_GCM) {
    const alg = cipherId === Cipher.AES_128_GCM ? "aes-128-gcm" : "aes-256-gcm";
    const d = createDecipheriv(alg, key, nonce, { authTagLength: AUTH_TAG_LEN });
    d.setAuthTag(tag);
    d.setAAD(aad);
    return Buffer.concat([d.update(ciphertext), d.final()]);
  }
  throw new SmbProtocolError({ status: 0, message: `unsupported cipher 0x${cipherId.toString(16)}` });
}

export function encryptMessage(
  plaintext: Buffer,
  keys: EncryptionKeys,
  sessionId: bigint,
  counter: bigint,
): Buffer {
  const nonce = counterNonce(counter, keys.cipherId);
  const header = Buffer.alloc(TRANSFORM_HEADER_SIZE);
  TRANSFORM_PROTOCOL_ID.copy(header, 0);
  // Signature (bytes 4..20) is left zero until we have the tag.
  nonce.copy(header, 20);
  // Remaining nonce-field bytes are already zero from alloc().
  header.writeUInt32LE(plaintext.length, 36);
  // Reserved (40..42) stays zero.
  header.writeUInt16LE(ENCRYPTED_FLAG, 42);
  header.writeBigUInt64LE(sessionId, 44);

  const aad = header.subarray(20, 52);
  const { ciphertext, tag } = aeadEncrypt(keys.cipherId, keys.encryption, nonce, aad, plaintext);
  tag.copy(header, 4);
  return Buffer.concat([header, ciphertext]);
}

export function decryptMessage(
  frame: Buffer,
  keys: EncryptionKeys,
  expectedSessionId: bigint,
): Buffer {
  if (frame.length < TRANSFORM_HEADER_SIZE) {
    throw new SmbProtocolError({ status: 0, message: "TRANSFORM frame too short" });
  }
  if (!isTransformHeader(frame)) {
    throw new SmbProtocolError({ status: 0, message: "TRANSFORM bad ProtocolId" });
  }
  const tag = frame.subarray(4, 20);
  const originalSize = frame.readUInt32LE(36);
  const flags = frame.readUInt16LE(42);
  if (flags !== ENCRYPTED_FLAG) {
    throw new SmbProtocolError({ status: 0, message: `TRANSFORM Flags=0x${flags.toString(16)}, expected 0x0001` });
  }
  const sessionId = frame.readBigUInt64LE(44);
  if (sessionId !== expectedSessionId) {
    throw new SmbProtocolError({ status: 0, message: "TRANSFORM SessionId mismatch" });
  }
  const ciphertext = frame.subarray(TRANSFORM_HEADER_SIZE);
  if (ciphertext.length !== originalSize) {
    throw new SmbProtocolError({
      status: 0,
      message: `TRANSFORM length mismatch: ciphertext=${ciphertext.length} OriginalMessageSize=${originalSize}`,
    });
  }
  const aad = frame.subarray(20, 52);
  const nonce = frame.subarray(20, 20 + nonceLength(keys.cipherId));
  try {
    return aeadDecrypt(keys.cipherId, keys.decryption, nonce, aad, ciphertext, tag);
  } catch (err) {
    if (err instanceof SmbProtocolError) throw err;
    throw new SmbProtocolError({
      status: 0,
      message: `TRANSFORM auth failure: ${(err as Error).message}`,
      cause: err,
    });
  }
}
