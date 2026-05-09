import { randomBytes } from "node:crypto";
import { Writer } from "../wire/buffer.js";
import { ntowfV2, hmacMd5 } from "./keys.js";

export const NTLMSSP_FLAGS = {
  NEGOTIATE_UNICODE: 0x00000001,
  NEGOTIATE_OEM: 0x00000002,
  REQUEST_TARGET: 0x00000004,
  NEGOTIATE_SIGN: 0x00000010,
  NEGOTIATE_SEAL: 0x00000020,
  NEGOTIATE_NTLM: 0x00000200,
  NEGOTIATE_DOMAIN_SUPPLIED: 0x00001000,
  NEGOTIATE_WORKSTATION_SUPPLIED: 0x00002000,
  NEGOTIATE_ALWAYS_SIGN: 0x00008000,
  NEGOTIATE_EXTENDED_SESSIONSECURITY: 0x00080000,
  NEGOTIATE_TARGET_INFO: 0x00800000,
  NEGOTIATE_VERSION: 0x02000000,
  NEGOTIATE_128: 0x20000000,
  NEGOTIATE_KEY_EXCH: 0x40000000,
  NEGOTIATE_56: 0x80000000,
} as const;

const SIGNATURE = Buffer.from("NTLMSSP\0");

export function encodeNegotiateMessage(): Buffer {
  const w = new Writer();
  w.bytes(SIGNATURE);
  w.u32(1);
  const flags =
    NTLMSSP_FLAGS.NEGOTIATE_UNICODE |
    NTLMSSP_FLAGS.NEGOTIATE_OEM |
    NTLMSSP_FLAGS.REQUEST_TARGET |
    NTLMSSP_FLAGS.NEGOTIATE_SIGN |
    NTLMSSP_FLAGS.NEGOTIATE_NTLM |
    NTLMSSP_FLAGS.NEGOTIATE_ALWAYS_SIGN |
    NTLMSSP_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY |
    NTLMSSP_FLAGS.NEGOTIATE_TARGET_INFO |
    NTLMSSP_FLAGS.NEGOTIATE_VERSION |
    NTLMSSP_FLAGS.NEGOTIATE_128 |
    NTLMSSP_FLAGS.NEGOTIATE_KEY_EXCH |
    NTLMSSP_FLAGS.NEGOTIATE_56;
  w.u32(flags >>> 0);
  // DomainNameFields (len, maxlen, offset) — empty
  w.u16(0); w.u16(0); w.u32(0);
  // WorkstationFields — empty
  w.u16(0); w.u16(0); w.u32(0);
  // Version (8 bytes) — zero
  w.bytes(Buffer.alloc(8));
  return w.buffer();
}

export interface NtlmChallenge {
  flags: number;
  serverChallenge: Buffer;
  targetName: string;
  targetInfo: Buffer;
}

export function decodeChallengeMessage(buf: Buffer): NtlmChallenge {
  if (!buf.subarray(0, 8).equals(SIGNATURE)) throw new Error("NTLMSSP: bad signature");
  if (buf.readUInt32LE(8) !== 2) throw new Error("NTLMSSP: not CHALLENGE");
  const tnLen = buf.readUInt16LE(12);
  const tnOffset = buf.readUInt32LE(16);
  const flags = buf.readUInt32LE(20);
  const serverChallenge = Buffer.from(buf.subarray(24, 32));
  const tiLen = buf.readUInt16LE(40);
  const tiOffset = buf.readUInt32LE(44);
  const targetName = tnLen > 0 ? Buffer.from(buf.subarray(tnOffset, tnOffset + tnLen)).toString("utf16le") : "";
  const targetInfo = tiLen > 0 ? Buffer.from(buf.subarray(tiOffset, tiOffset + tiLen)) : Buffer.alloc(0);
  return { flags, serverChallenge, targetName, targetInfo };
}

export interface NtlmV2Inputs {
  password: string;
  username: string;
  domain: string;
  serverChallenge: Buffer;
  clientChallenge: Buffer;
  targetInfo: Buffer;
  time?: bigint; // Windows FILETIME (100ns intervals since 1601). If omitted, "now".
}

export interface NtlmV2Outputs {
  ntChallengeResponse: Buffer; // NTProofStr (16) || temp
  lmChallengeResponse: Buffer; // 24 bytes
  sessionBaseKey: Buffer; // 16 bytes
}

function nowFiletime(): bigint {
  const epochDiffSec = 11644473600n;
  const ms = BigInt(Date.now());
  return (ms / 1000n + epochDiffSec) * 10000000n + (ms % 1000n) * 10000n;
}

export function computeNtlmV2(inp: NtlmV2Inputs): NtlmV2Outputs {
  const responseKeyNT = ntowfV2(inp.password, inp.username, inp.domain);
  const time = inp.time ?? nowFiletime();
  const tempW = new Writer();
  tempW.u8(0x01); // RespType
  tempW.u8(0x01); // HiRespType
  tempW.bytes(Buffer.alloc(6));
  tempW.u64(time);
  tempW.bytes(inp.clientChallenge);
  tempW.u32(0); // Reserved
  tempW.bytes(inp.targetInfo);
  tempW.u32(0); // EOL AV pair already present in targetInfo? Tests pass it explicitly; appending zero word keeps Windows happy.
  const temp = tempW.buffer();

  const ntProofInput = Buffer.concat([inp.serverChallenge, temp]);
  const ntProofStr = hmacMd5(responseKeyNT, ntProofInput);
  const ntChallengeResponse = Buffer.concat([ntProofStr, temp]);

  const lm = hmacMd5(responseKeyNT, Buffer.concat([inp.serverChallenge, inp.clientChallenge]));
  const lmChallengeResponse = Buffer.concat([lm, inp.clientChallenge]);

  const sessionBaseKey = hmacMd5(responseKeyNT, ntProofStr);
  return { ntChallengeResponse, lmChallengeResponse, sessionBaseKey };
}

export interface AuthenticateInputs {
  domain: string;
  username: string;
  workstation?: string;
  ntChallengeResponse: Buffer;
  lmChallengeResponse: Buffer;
  encryptedRandomSessionKey: Buffer; // 16 bytes
  flags: number;
  /** When provided, recompute MIC = HMAC-MD5(ExportedSessionKey, NEG||CHAL||AUTH). */
  mic?: { exportedSessionKey: Buffer; negotiateMessage: Buffer; challengeMessage: Buffer };
}

export function encodeAuthenticateMessage(inp: AuthenticateInputs): Buffer {
  const headerSize = 88; // signature(8) + type(4) + 6 fields(48) + flags(4) + version(8) + MIC(16)
  const domainBytes = Buffer.from(inp.domain, "utf16le");
  const userBytes = Buffer.from(inp.username, "utf16le");
  const wsBytes = Buffer.from(inp.workstation ?? "", "utf16le");

  let off = headerSize;
  const lmOff = off; off += inp.lmChallengeResponse.length;
  const ntOff = off; off += inp.ntChallengeResponse.length;
  const domainOff = off; off += domainBytes.length;
  const userOff = off; off += userBytes.length;
  const wsOff = off; off += wsBytes.length;
  const sessKeyOff = off; off += inp.encryptedRandomSessionKey.length;
  const total = off;

  const w = new Writer();
  w.bytes(SIGNATURE);
  w.u32(3);
  // LM
  w.u16(inp.lmChallengeResponse.length); w.u16(inp.lmChallengeResponse.length); w.u32(lmOff);
  // NT
  w.u16(inp.ntChallengeResponse.length); w.u16(inp.ntChallengeResponse.length); w.u32(ntOff);
  // Domain
  w.u16(domainBytes.length); w.u16(domainBytes.length); w.u32(domainOff);
  // User
  w.u16(userBytes.length); w.u16(userBytes.length); w.u32(userOff);
  // Workstation
  w.u16(wsBytes.length); w.u16(wsBytes.length); w.u32(wsOff);
  // EncryptedRandomSessionKey
  w.u16(inp.encryptedRandomSessionKey.length); w.u16(inp.encryptedRandomSessionKey.length); w.u32(sessKeyOff);
  // Flags
  w.u32(inp.flags >>> 0);
  // Version
  w.bytes(Buffer.alloc(8));
  // MIC placeholder (16 bytes)
  const micPos = w.offset;
  w.bytes(Buffer.alloc(16));
  // Payload
  w.bytes(inp.lmChallengeResponse);
  w.bytes(inp.ntChallengeResponse);
  w.bytes(domainBytes);
  w.bytes(userBytes);
  w.bytes(wsBytes);
  w.bytes(inp.encryptedRandomSessionKey);
  const buf = w.buffer();
  if (buf.length !== total) throw new Error(`AUTH msg length mismatch: ${buf.length} vs ${total}`);

  if (inp.mic) {
    const concat = Buffer.concat([inp.mic.negotiateMessage, inp.mic.challengeMessage, buf]);
    const mic = hmacMd5(inp.mic.exportedSessionKey, concat);
    mic.copy(buf, micPos, 0, 16);
  }
  return buf;
}

export function generateClientChallenge(): Buffer {
  return randomBytes(8);
}

export function generateExportedSessionKey(): Buffer {
  return randomBytes(16);
}

export function rc4(key: Buffer, data: Buffer): Buffer {
  // Tiny RC4 — only used to wrap the 16-byte ExportedSessionKey.
  const S = new Uint8Array(256);
  for (let i = 0; i < 256; i++) S[i] = i;
  let j = 0;
  for (let i = 0; i < 256; i++) {
    j = (j + S[i]! + key[i % key.length]!) & 0xff;
    [S[i], S[j]] = [S[j]!, S[i]!];
  }
  const out = Buffer.alloc(data.length);
  let i = 0; j = 0;
  for (let k = 0; k < data.length; k++) {
    i = (i + 1) & 0xff;
    j = (j + S[i]!) & 0xff;
    [S[i], S[j]] = [S[j]!, S[i]!];
    const t = (S[i]! + S[j]!) & 0xff;
    out[k] = data[k]! ^ S[t]!;
  }
  return out;
}
