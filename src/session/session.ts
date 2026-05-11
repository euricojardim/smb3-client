import type { Connection } from "../connection/connection.js";
import {
  encodeNegotiateMessage,
  decodeChallengeMessage,
  encodeAuthenticateMessage,
  computeNtlmV2,
  generateClientChallenge,
  generateExportedSessionKey,
  rc4,
  NTLMSSP_FLAGS,
} from "./ntlm.js";
import { wrapInitNegToken, wrapNegTokenResp, extractNtlmFromResp } from "./spnego.js";
import { kdfSp800108CounterHmacSha256 } from "./keys.js";
import { encodeSessionSetupRequest, decodeSessionSetupResponse } from "../wire/structs/sessionSetup.js";
import { SmbCommand, NTStatus, Dialect, SecurityMode, Cipher, isSuccess } from "../wire/commands.js";
import { SmbAuthError } from "../errors.js";
import { sign, verify } from "../connection/signing.js";
import {
  encryptMessage,
  decryptMessage,
  type Encryptor,
  type EncryptionKeys,
} from "../connection/encryption.js";

export interface SessionCreds {
  username: string;
  password: string;
  domain?: string;
}

export type EncryptionMode = "required" | "if-offered" | "disabled";
export type SigningMode = "disabled" | "if-offered" | "required";

function pickCipher(offered: number[], preferred: number[]): number | undefined {
  for (const c of preferred) {
    if (offered.includes(c)) return c;
  }
  return undefined;
}

function cipherKeyLength(cipherId: number): number {
  return cipherId === Cipher.AES_256_CCM || cipherId === Cipher.AES_256_GCM ? 32 : 16;
}

export class Session {
  sessionId: bigint = 0n;
  signingKey: Buffer | null = null;
  encryptionKeys: EncryptionKeys | null = null;
  /** True when global encryption mode is "required" — every non-NEGOTIATE/SESSION_SETUP request encrypts. */
  globalEncrypt = false;
  private closed = false;
  private readonly mode: EncryptionMode;
  private readonly signingMode: SigningMode;
  private readonly preferredCiphers: number[];

  constructor(
    private readonly conn: Connection,
    private readonly creds: SessionCreds,
    opts: { encryption?: EncryptionMode; ciphers?: number[]; signing?: SigningMode } = {},
  ) {
    this.mode = opts.encryption ?? "if-offered";
    this.signingMode = opts.signing ?? "if-offered";
    this.preferredCiphers = opts.ciphers ?? [
      Cipher.AES_128_GCM,
      Cipher.AES_128_CCM,
      Cipher.AES_256_GCM,
      Cipher.AES_256_CCM,
    ];
  }

  async setup(): Promise<void> {
    const negotiated = this.conn.state;
    if (!negotiated) throw new Error("Session.setup: connection not negotiated");
    const dialect = negotiated.dialect;

    // If the user explicitly opted out of signing but the server demands it,
    // fail loudly rather than silently sending signed frames or failing later.
    if (
      this.signingMode === "disabled" &&
      (negotiated.securityMode & SecurityMode.SIGNING_REQUIRED) !== 0
    ) {
      throw new SmbAuthError({
        status: 0,
        message: "server requires signing, but client has signing disabled",
      });
    }

    // First leg: send NTLMSSP NEGOTIATE wrapped in SPNEGO NegTokenInit.
    const ntlmNeg = encodeNegotiateMessage();
    const blob1 = wrapInitNegToken(ntlmNeg);
    const req1 = encodeSessionSetupRequest({
      securityMode: SecurityMode.SIGNING_ENABLED,
      capabilities: 0,
      blob: blob1,
    });
    const resp1 = await this.conn.send(SmbCommand.SESSION_SETUP, req1, { creditCharge: 1 });
    if (resp1.header.status !== NTStatus.STATUS_MORE_PROCESSING_REQUIRED) {
      throw new SmbAuthError({
        status: resp1.header.status,
        message: `SESSION_SETUP NEG expected MORE_PROCESSING_REQUIRED, got ${resp1.header.status.toString(16)}`,
      });
    }
    this.sessionId = resp1.header.sessionId;
    const sessSetup1 = decodeSessionSetupResponse(resp1.body, 64);
    const ntlmChalBlob = extractNtlmFromResp(sessSetup1.securityBuffer);
    if (ntlmChalBlob.length === 0) {
      throw new SmbAuthError({ status: 0, message: "no NTLM CHALLENGE in server response" });
    }
    const challenge = decodeChallengeMessage(ntlmChalBlob);

    // Compute NTLMv2 outputs.
    const clientChallenge = generateClientChallenge();
    const ntlmV2 = computeNtlmV2({
      password: this.creds.password,
      username: this.creds.username,
      domain: this.creds.domain ?? "",
      serverChallenge: challenge.serverChallenge,
      clientChallenge,
      targetInfo: challenge.targetInfo,
    });

    const exportedSessionKey = generateExportedSessionKey();
    const encryptedRandomSessionKey = rc4(ntlmV2.sessionBaseKey, exportedSessionKey);

    const flags =
      NTLMSSP_FLAGS.NEGOTIATE_UNICODE |
      NTLMSSP_FLAGS.NEGOTIATE_SIGN |
      NTLMSSP_FLAGS.NEGOTIATE_NTLM |
      NTLMSSP_FLAGS.NEGOTIATE_ALWAYS_SIGN |
      NTLMSSP_FLAGS.NEGOTIATE_EXTENDED_SESSIONSECURITY |
      NTLMSSP_FLAGS.NEGOTIATE_TARGET_INFO |
      NTLMSSP_FLAGS.NEGOTIATE_VERSION |
      NTLMSSP_FLAGS.NEGOTIATE_128 |
      NTLMSSP_FLAGS.NEGOTIATE_KEY_EXCH |
      NTLMSSP_FLAGS.NEGOTIATE_56;

    const auth = encodeAuthenticateMessage({
      domain: this.creds.domain ?? "",
      username: this.creds.username,
      ntChallengeResponse: ntlmV2.ntChallengeResponse,
      lmChallengeResponse: ntlmV2.lmChallengeResponse,
      encryptedRandomSessionKey,
      flags,
      mic: {
        exportedSessionKey,
        negotiateMessage: ntlmNeg,
        challengeMessage: ntlmChalBlob,
      },
    });
    const blob2 = wrapNegTokenResp(auth);
    const req2 = encodeSessionSetupRequest({
      securityMode: SecurityMode.SIGNING_ENABLED,
      capabilities: 0,
      blob: blob2,
    });
    const resp2 = await this.conn.send(SmbCommand.SESSION_SETUP, req2, {
      creditCharge: 1,
      sessionId: this.sessionId,
    });
    if (!isSuccess(resp2.header.status)) {
      throw new SmbAuthError({ status: resp2.header.status, message: "SESSION_SETUP AUTH failed" });
    }

    // Derive signing key
    if (dialect === Dialect.SMB_2_1_0 || dialect === Dialect.SMB_2_0_2) {
      this.signingKey = exportedSessionKey;
    } else if (dialect === Dialect.SMB_3_0_0 || dialect === Dialect.SMB_3_0_2) {
      this.signingKey = kdfSp800108CounterHmacSha256(
        exportedSessionKey,
        Buffer.from("SMB2AESCMAC\0", "ascii"),
        Buffer.from("SmbSign\0", "ascii"),
        16,
      );
    } else if (dialect === Dialect.SMB_3_1_1) {
      const preauth = this.conn.preauthDigest();
      this.signingKey = kdfSp800108CounterHmacSha256(
        exportedSessionKey,
        Buffer.from("SMBSigningKey\0", "ascii"),
        preauth,
        16,
      );
    } else {
      throw new SmbAuthError({ status: 0, message: `unsupported dialect ${dialect.toString(16)}` });
    }

    // Register the verifier on the connection so every subsequent signed response is checked.
    const signingKey = this.signingKey!;
    this.conn.setVerifier((frame, sig) => verify(frame, sig, signingKey, dialect));
    this.applyCancelSigner();

    // SMB 3.x message encryption (MS-SMB2 §3.1.4.3 / §3.2.4.1.5).
    if (this.mode !== "disabled" && this.dialectSupportsEncryption(dialect)) {
      const cipherId = this.selectCipher(dialect, negotiated.cipherIds);
      if (cipherId !== undefined) {
        const keys = this.deriveEncryptionKeys(dialect, exportedSessionKey, cipherId);
        this.encryptionKeys = keys;
        const sessionId = this.sessionId;
        let counter = 1n;
        const enc: Encryptor = {
          encrypt: (plaintext: Buffer): Buffer => {
            const c = counter++;
            return encryptMessage(plaintext, keys, sessionId, c);
          },
          decrypt: (frame: Buffer): Buffer => decryptMessage(frame, keys, sessionId),
        };
        this.conn.setEncryptor(enc);
        this.globalEncrypt = this.mode === "required" || this.mode === "if-offered";
        // Once we agree to encrypt, the connection refuses plaintext responses
        // (MS-SMB2 §3.2.5.1.1 — guards against silent downgrade).
        this.conn.setEncryptionRequired(this.globalEncrypt);
      } else if (this.mode === "required") {
        throw new SmbAuthError({
          status: 0,
          message: "encryption required but server did not offer a supported cipher",
        });
      }
    } else if (this.mode === "required") {
      throw new SmbAuthError({
        status: 0,
        message: `encryption required but dialect 0x${dialect.toString(16)} does not support it`,
      });
    }
  }

  private dialectSupportsEncryption(dialect: number): boolean {
    return (
      dialect === Dialect.SMB_3_0_0 ||
      dialect === Dialect.SMB_3_0_2 ||
      dialect === Dialect.SMB_3_1_1
    );
  }

  private selectCipher(dialect: number, offeredByServer: number[] | undefined): number | undefined {
    if (dialect === Dialect.SMB_3_0_0 || dialect === Dialect.SMB_3_0_2) {
      // Pre-3.1.1: encryption is signalled by the SMB2_GLOBAL_CAP_ENCRYPTION capability bit,
      // and the cipher is always AES-128-CCM. The server has no per-cipher choice.
      const conn = this.conn.state;
      const serverHasEncryption =
        conn !== null && (conn.capabilities & 0x00000040) !== 0; // Capability.ENCRYPTION
      return serverHasEncryption ? Cipher.AES_128_CCM : undefined;
    }
    // 3.1.1: server picks one cipher from those we offered.
    if (offeredByServer === undefined || offeredByServer.length === 0) return undefined;
    const chosen = pickCipher(offeredByServer, this.preferredCiphers);
    return chosen;
  }

  private deriveEncryptionKeys(
    dialect: number,
    sessionKey: Buffer,
    cipherId: number,
  ): EncryptionKeys {
    const keyLen = cipherKeyLength(cipherId);
    if (dialect === Dialect.SMB_3_0_0 || dialect === Dialect.SMB_3_0_2) {
      // Note: "ServerIn " has a trailing ASCII space per MS-SMB2 §3.1.4.2.
      const encryption = kdfSp800108CounterHmacSha256(
        sessionKey,
        Buffer.from("SMB2AESCCM\0", "ascii"),
        Buffer.from("ServerIn \0", "ascii"),
        keyLen,
      );
      const decryption = kdfSp800108CounterHmacSha256(
        sessionKey,
        Buffer.from("SMB2AESCCM\0", "ascii"),
        Buffer.from("ServerOut\0", "ascii"),
        keyLen,
      );
      return { encryption, decryption, cipherId };
    }
    // SMB 3.1.1
    const preauth = this.conn.preauthDigest();
    const encryption = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMBC2SCipherKey\0", "ascii"),
      preauth,
      keyLen,
    );
    const decryption = kdfSp800108CounterHmacSha256(
      sessionKey,
      Buffer.from("SMBS2CCipherKey\0", "ascii"),
      preauth,
      keyLen,
    );
    return { encryption, decryption, cipherId };
  }

  async close(): Promise<void> {
    if (this.closed || this.sessionId === 0n) return;
    this.closed = true;
    // LOGOFF body is StructureSize(2) + Reserved(2) = 4 bytes
    const body = Buffer.from([0x04, 0x00, 0x00, 0x00]);
    const signing = this.makeSigning();
    await this.conn.send(SmbCommand.LOGOFF, body, {
      sessionId: this.sessionId,
      ...(signing !== undefined ? { signing } : {}),
      encrypt: this.globalEncrypt,
    });
  }

  makeSigning(): { sign: (msg: Buffer) => Buffer } | undefined {
    if (this.signingMode === "disabled") return undefined;
    const key = this.signingKey;
    const dialect = this.conn.state?.dialect;
    if (!key || !dialect) return undefined;
    return {
      sign: (msg: Buffer): Buffer => sign(msg, key, dialect),
    };
  }

  /**
   * Registers a CANCEL frame signer on the Connection unless signing is disabled.
   * Under `signing: "disabled"`, the Connection's CANCEL path stays null-safe and
   * cancellations go out unsigned — consistent with MS-SMB2 §3.2.4.24 only when
   * the session never agreed to sign in the first place.
   */
  private applyCancelSigner(): void {
    if (this.signingMode === "disabled") return;
    const key = this.signingKey;
    const dialect = this.conn.state?.dialect;
    if (!key || dialect === undefined) return;
    this.conn.setCancelSigner((msg) => sign(msg, key, dialect));
  }
}
