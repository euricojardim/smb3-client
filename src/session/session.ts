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
import { SmbCommand, NTStatus, Dialect, SecurityMode, isSuccess } from "../wire/commands.js";
import { SmbAuthError } from "../errors.js";
import { sign, verify } from "../connection/signing.js";

export interface SessionCreds {
  username: string;
  password: string;
  domain?: string;
}

export class Session {
  sessionId: bigint = 0n;
  signingKey: Buffer | null = null;
  private closed = false;

  constructor(
    private readonly conn: Connection,
    private readonly creds: SessionCreds,
  ) {}

  async setup(): Promise<void> {
    const negotiated = this.conn.state;
    if (!negotiated) throw new Error("Session.setup: connection not negotiated");
    const dialect = negotiated.dialect;

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
  }

  async close(): Promise<void> {
    if (this.closed || this.sessionId === 0n) return;
    this.closed = true;
    // LOGOFF body is StructureSize(2) + Reserved(2) = 4 bytes
    const body = Buffer.from([0x04, 0x00, 0x00, 0x00]);
    const signing = this.makeSigning();
    const sendOpts = signing
      ? { sessionId: this.sessionId, signing }
      : { sessionId: this.sessionId };
    await this.conn.send(SmbCommand.LOGOFF, body, sendOpts);
  }

  makeSigning(): { sign: (msg: Buffer) => Buffer } | undefined {
    const key = this.signingKey;
    const dialect = this.conn.state?.dialect;
    if (!key || !dialect) return undefined;
    return {
      sign: (msg: Buffer): Buffer => sign(msg, key, dialect),
    };
  }
}
