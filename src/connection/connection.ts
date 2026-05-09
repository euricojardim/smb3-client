import { randomBytes } from "node:crypto";
import { EventEmitter } from "node:events";
import type { Transport } from "../transport/socket.js";
import { frame as makeFrame } from "../transport/framer.js";
import { encodeHeader, decodeHeader, SmbHeader, SMB2_HEADER_SIZE } from "../wire/smb2-header.js";
import {
  SmbCommand,
  Dialect,
  HeaderFlag,
  SecurityMode,
  Capability,
  isSuccess,
  isPending,
  statusName,
} from "../wire/commands.js";
import { encodeNegotiateRequest, decodeNegotiateResponse, NegotiateResponse } from "../wire/structs/negotiate.js";
import { encodeCancelRequest } from "../wire/structs/cancel.js";
import { CreditWindow } from "./credits.js";
import { PreauthHash } from "./preauth.js";
import { SmbProtocolError } from "../errors.js";

export interface ConnectionOpenOptions {
  clientGuid?: Buffer;
  dialects?: number[];
  capabilities?: number;
  securityMode?: number;
}

export interface NegotiatedConnection {
  dialect: number;
  serverGuid: Buffer;
  capabilities: number;
  securityMode: number;
  maxReadSize: number;
  maxWriteSize: number;
  maxTransactSize: number;
  preauthHashAlg?: number;
  preauthSalt?: Buffer;
  securityBuffer: Buffer;
}

interface PendingRequest {
  resolve: (v: { header: SmbHeader; body: Buffer }) => void;
  reject: (err: unknown) => void;
  expectsAsync: boolean;
}

export interface SendOptions {
  treeId?: number;
  sessionId?: bigint;
  creditCharge?: number;
  flags?: number;
  signing?: { sign: (msg: Buffer) => Buffer };
}

export class Connection extends EventEmitter {
  private nextMessageId: bigint = 0n;
  private pendingByMessageId = new Map<string, PendingRequest>();
  private pendingByAsyncId = new Map<string, PendingRequest>();
  private credits = new CreditWindow(1);
  private preauth = new PreauthHash();
  private negotiated: NegotiatedConnection | null = null;
  private closed = false;
  private verifier: ((frame: Buffer, sig: Buffer) => boolean) | null = null;

  constructor(private readonly transport: Transport) {
    super();
    transport.on("message", (msg: Buffer) => this.onMessage(msg));
    transport.on("close", () => this.onClose());
    transport.on("error", (err: Error) => this.onError(err));
  }

  get state(): NegotiatedConnection | null {
    return this.negotiated;
  }

  async open(opts: ConnectionOpenOptions = {}): Promise<NegotiatedConnection> {
    const dialects = opts.dialects ?? [
      Dialect.SMB_2_1_0,
      Dialect.SMB_3_0_0,
      Dialect.SMB_3_0_2,
      Dialect.SMB_3_1_1,
    ];
    const clientGuid = opts.clientGuid ?? randomBytes(16);
    const preauthSalt = randomBytes(32);
    const reqBody = encodeNegotiateRequest({
      dialects,
      clientGuid,
      capabilities: opts.capabilities ?? Capability.LARGE_MTU,
      securityMode: opts.securityMode ?? SecurityMode.SIGNING_ENABLED,
      preauthSalt,
    });
    const result = await this.send(SmbCommand.NEGOTIATE, reqBody, { creditCharge: 0 });
    if (!isSuccess(result.header.status)) {
      throw new SmbProtocolError({
        status: result.header.status,
        message: `NEGOTIATE failed: ${statusName(result.header.status)}`,
      });
    }
    const resp: NegotiateResponse = decodeNegotiateResponse(result.body, SMB2_HEADER_SIZE);
    const negotiated: NegotiatedConnection = {
      dialect: resp.dialect,
      serverGuid: resp.serverGuid,
      capabilities: resp.capabilities,
      securityMode: resp.securityMode,
      maxReadSize: resp.maxReadSize,
      maxWriteSize: resp.maxWriteSize,
      maxTransactSize: resp.maxTransactSize,
      securityBuffer: resp.securityBuffer,
      ...(resp.preauthHashAlg !== undefined ? { preauthHashAlg: resp.preauthHashAlg } : {}),
      ...(resp.preauthSalt !== undefined ? { preauthSalt: resp.preauthSalt } : {}),
    };
    this.negotiated = negotiated;
    return this.negotiated;
  }

  async send(
    command: number,
    body: Buffer,
    opts: SendOptions = {},
  ): Promise<{ header: SmbHeader; body: Buffer }> {
    if (this.closed) throw new SmbProtocolError({ status: 0, message: "connection closed" });
    const charge = opts.creditCharge ?? 1;
    if (charge > 0) await this.credits.take(charge);
    const messageId = this.nextMessageId++;
    const flags = opts.flags ?? 0;
    let header = encodeHeader({
      command,
      creditCharge: Math.max(charge, 1),
      creditRequestResponse: 1,
      flags,
      messageId,
      sessionId: opts.sessionId ?? 0n,
      treeId: opts.treeId ?? 0,
      status: 0,
    });
    let frameBuf = Buffer.concat([header, body]);
    if (opts.signing) {
      // Set SIGNED flag, sign full frame, write signature back into header bytes.
      const signedFlags = flags | HeaderFlag.SIGNED;
      header = encodeHeader({
        command,
        creditCharge: Math.max(charge, 1),
        creditRequestResponse: 1,
        flags: signedFlags,
        messageId,
        sessionId: opts.sessionId ?? 0n,
        treeId: opts.treeId ?? 0,
        status: 0,
      });
      frameBuf = Buffer.concat([header, body]);
      const sig = opts.signing.sign(frameBuf);
      sig.copy(frameBuf, 48); // signature offset within header is 48
    }

    // Pre-auth hash: NEGOTIATE and SESSION_SETUP requests/responses feed it.
    if (command === SmbCommand.NEGOTIATE || command === SmbCommand.SESSION_SETUP) {
      this.preauth.update(frameBuf);
    }

    const promise = new Promise<{ header: SmbHeader; body: Buffer }>((resolve, reject) => {
      this.pendingByMessageId.set(messageId.toString(), {
        resolve,
        reject,
        expectsAsync: command === SmbCommand.CHANGE_NOTIFY,
      });
    });
    this.transport.send(makeFrame(frameBuf));
    return promise;
  }

  preauthDigest(): Buffer {
    return this.preauth.digest();
  }

  setVerifier(fn: (frame: Buffer, sig: Buffer) => boolean): void {
    this.verifier = fn;
  }

  private onMessage(msg: Buffer): void {
    let parsed: ReturnType<typeof decodeHeader>;
    try {
      parsed = decodeHeader(msg);
    } catch (err) {
      this.fail(new SmbProtocolError({ status: 0, message: `bad SMB2 header: ${(err as Error).message}` }));
      return;
    }
    const { header } = parsed;
    const body = Buffer.from(msg.subarray(SMB2_HEADER_SIZE));

    // Verify signature on signed responses when a verifier is registered.
    if ((header.flags & HeaderFlag.SIGNED) !== 0 && this.verifier !== null) {
      const working = Buffer.from(msg);
      working.fill(0, 48, 64); // zero the Signature field before computing
      const sig = header.signature ?? Buffer.alloc(16);
      if (!this.verifier(working, sig)) {
        this.fail(new SmbProtocolError({ status: 0, message: "signature verify failed" }));
        return;
      }
    }

    // Replenish credits.
    this.credits.release(header.creditRequestResponse);
    // Pre-auth hash update for NEGOTIATE/SESSION_SETUP responses.
    if (header.command === SmbCommand.NEGOTIATE || header.command === SmbCommand.SESSION_SETUP) {
      this.preauth.update(msg);
    }

    const messageKey = header.messageId.toString();
    const pending = this.pendingByMessageId.get(messageKey);
    if (!pending) {
      // Could be a pure ASYNC final response keyed by AsyncId.
      if (header.asyncId !== undefined) {
        const a = this.pendingByAsyncId.get(header.asyncId.toString());
        if (a) {
          this.pendingByAsyncId.delete(header.asyncId.toString());
          a.resolve({ header, body });
          return;
        }
      }
      // Unsolicited; ignore.
      return;
    }

    if (isPending(header.status) && header.asyncId !== undefined) {
      // Interim response: keep the pending entry alive but key by AsyncId for the final.
      this.pendingByAsyncId.set(header.asyncId.toString(), pending);
      this.pendingByMessageId.delete(messageKey);
      return;
    }

    this.pendingByMessageId.delete(messageKey);
    pending.resolve({ header, body });
  }

  private onClose(): void {
    this.closed = true;
    this.fail(new SmbProtocolError({ status: 0, message: "connection closed" }));
    this.emit("close");
  }

  private onError(err: Error): void {
    this.fail(new SmbProtocolError({ status: 0, message: err.message, cause: err }));
  }

  private fail(err: SmbProtocolError): void {
    for (const p of this.pendingByMessageId.values()) p.reject(err);
    for (const p of this.pendingByAsyncId.values()) p.reject(err);
    this.pendingByMessageId.clear();
    this.pendingByAsyncId.clear();
  }

  cancel(opts: { messageId: bigint; asyncId?: bigint; sessionId?: bigint; treeId?: number }): void {
    if (this.closed) return;
    const flags = opts.asyncId !== undefined ? HeaderFlag.ASYNC_COMMAND : 0;
    const header = encodeHeader({
      command: SmbCommand.CANCEL,
      creditCharge: 1,
      creditRequestResponse: 0,
      flags,
      messageId: opts.messageId,
      sessionId: opts.sessionId ?? 0n,
      ...(opts.asyncId !== undefined
        ? { asyncId: opts.asyncId }
        : { treeId: opts.treeId ?? 0 }),
      status: 0,
    });
    const body = encodeCancelRequest();
    this.transport.send(makeFrame(Buffer.concat([header, body])));
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.transport.close();
  }
}
