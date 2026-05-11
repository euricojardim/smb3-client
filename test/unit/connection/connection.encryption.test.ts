import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import {
  encryptMessage,
  decryptMessage,
  isTransformHeader,
  TRANSFORM_HEADER_SIZE,
  type Encryptor,
  type EncryptionKeys,
} from "../../../src/connection/encryption.js";
import { Cipher, Dialect, SmbCommand } from "../../../src/wire/commands.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { SmbProtocolError } from "../../../src/errors.js";

function makeKeys(): EncryptionKeys {
  return {
    encryption: Buffer.alloc(16, 0x77),
    decryption: Buffer.alloc(16, 0x88),
    cipherId: Cipher.AES_128_GCM,
  };
}

function makeEncryptor(keys: EncryptionKeys, sessionId: bigint): Encryptor {
  let ctr = 1n;
  return {
    encrypt: (pdu) => encryptMessage(pdu, keys, sessionId, ctr++),
    decrypt: (frame) => decryptMessage(frame, keys, sessionId),
  };
}

describe("Connection encryption — outbound", () => {
  it("wraps outbound frames in a TRANSFORM_HEADER when encrypt: true and encryptor is installed", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4)); // strip NBSS 4-byte prefix
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    const keys = makeKeys();
    const sessionId = 0xdeadbeefn;
    conn.setEncryptor(makeEncryptor(keys, sessionId));

    void conn.send(SmbCommand.READ, Buffer.from([0x01, 0x02, 0x03]), {
      sessionId,
      encrypt: true,
    });
    await new Promise((r) => setImmediate(r));

    expect(captured).not.toBeNull();
    const wire = captured!;
    expect(isTransformHeader(wire)).toBe(true);
    expect(wire.readBigUInt64LE(44)).toBe(sessionId);

    // Decrypting with the same keys yields the original SMB2 header + body.
    const recvKeys: EncryptionKeys = { ...keys, decryption: keys.encryption };
    const plaintext = decryptMessage(wire, recvKeys, sessionId);
    expect(plaintext.length).toBe(64 + 3);
    expect(plaintext.subarray(0, 4)).toEqual(Buffer.from([0xfe, 0x53, 0x4d, 0x42]));
  });

  it("does NOT wrap when encrypt: false (signing path stays plaintext)", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    conn.setEncryptor(makeEncryptor(makeKeys(), 1n));

    void conn.send(SmbCommand.READ, Buffer.from([0x01]), { sessionId: 1n, encrypt: false });
    await new Promise((r) => setImmediate(r));
    expect(isTransformHeader(captured!)).toBe(false);
  });

  it("does NOT sign when encrypt: true (signature field stays zero, SIGNED flag clear)", async () => {
    const ft = new FakeTransport();
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const keys = makeKeys();
    const sessionId = 0x42n;
    conn.setEncryptor(makeEncryptor(keys, sessionId));

    void conn.send(SmbCommand.READ, Buffer.from([0xaa]), {
      sessionId,
      signing: { sign: () => Buffer.alloc(16, 0xff) },
      encrypt: true,
    });
    await new Promise((r) => setImmediate(r));

    const recvKeys: EncryptionKeys = { ...keys, decryption: keys.encryption };
    const inner = decryptMessage(captured!, recvKeys, sessionId);
    // Signature field at bytes 48..64 is all zero (no signing happened).
    expect(inner.subarray(48, 64)).toEqual(Buffer.alloc(16));
    // SIGNED flag (0x08) is NOT set in the flags field at offset 16.
    expect(inner.readUInt32LE(16) & 0x08).toBe(0);
  });
});

describe("Connection encryption — inbound", () => {
  it("decrypts inbound TRANSFORM frames before dispatch", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    const keys = makeKeys();
    const sessionId = 0xabc123n;
    // Encryptor uses `decryption` for inbound; map encryption key (server side) to client's decryption.
    const recvKeys: EncryptionKeys = { ...keys, decryption: keys.encryption };
    conn.setEncryptor(makeEncryptor(recvKeys, sessionId));

    // Send a request and capture its messageId so we can craft a matching encrypted response.
    let outMsgId: bigint | null = null;
    ft.onSend((frame) => {
      const wire = frame.subarray(4);
      if (isTransformHeader(wire)) {
        const inner = decryptMessage(wire, recvKeys, sessionId);
        outMsgId = inner.readBigUInt64LE(24);
      }
    });
    const reqPromise = conn.send(SmbCommand.READ, Buffer.from([0x00]), {
      sessionId,
      encrypt: true,
    });

    await new Promise((r) => setImmediate(r));
    expect(outMsgId).not.toBeNull();

    // Server crafts an encrypted SMB2 READ response with the same messageId.
    const respHeader = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0x1, // SERVER_TO_REDIR
      messageId: outMsgId!,
      sessionId,
      treeId: 0,
      status: 0,
    });
    const respBody = Buffer.from([0x05, 0x00]); // throwaway body
    const respPdu = Buffer.concat([respHeader, respBody]);
    const respWire = encryptMessage(respPdu, recvKeys, sessionId, 99n);
    ft.deliver(respWire);

    const got = await reqPromise;
    expect(got.header.sessionId).toBe(sessionId);
    expect(got.body).toEqual(respBody);
  });

  it("fails the connection when an encrypted frame arrives without an encryptor", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const onClose = new Promise<void>((resolve) => conn.on("close", resolve));

    let closed = false;
    conn.on("close", () => { closed = true; });

    // No setEncryptor() call — feed a transform frame anyway.
    const fakeFrame = Buffer.alloc(TRANSFORM_HEADER_SIZE + 10);
    fakeFrame[0] = 0xfd; fakeFrame[1] = 0x53; fakeFrame[2] = 0x4d; fakeFrame[3] = 0x42;
    ft.deliver(fakeFrame);

    // Issue a send to capture the rejection.
    const p = conn.send(SmbCommand.READ, Buffer.alloc(0));
    await expect(p).rejects.toBeInstanceOf(SmbProtocolError);
    // onClose is not strictly required here; we just check rejection.
    void onClose; void closed;
  });
});

describe("Connection encryption — downgrade protection", () => {
  it("rejects a plaintext non-SESSION_SETUP response after encryption is required", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    const keys = makeKeys();
    const sessionId = 0x55n;
    conn.setEncryptor(makeEncryptor(keys, sessionId));
    conn.setEncryptionRequired(true);

    // Pre-register a pending request so onMessage has something to reject through.
    const reqPromise = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId });
    await new Promise((r) => setImmediate(r));

    // Server "responds" in plaintext (simulates an active downgrade or buggy server).
    const plain = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0x1, // SERVER_TO_REDIR
      messageId: 0n,
      sessionId,
      treeId: 0,
      status: 0,
    });
    ft.deliver(Buffer.concat([plain, Buffer.alloc(0)]));

    await expect(reqPromise).rejects.toBeInstanceOf(SmbProtocolError);
    await expect(reqPromise).rejects.toThrow(/plaintext response received but session requires encryption/);
  });

  it("still accepts plaintext SESSION_SETUP responses (legitimate during re-auth)", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    conn.setEncryptor(makeEncryptor(makeKeys(), 0x55n));
    conn.setEncryptionRequired(true);

    const reqPromise = conn.send(SmbCommand.SESSION_SETUP, Buffer.alloc(0), { sessionId: 0x55n });
    await new Promise((r) => setImmediate(r));

    const plain = encodeHeader({
      command: SmbCommand.SESSION_SETUP,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0x1,
      messageId: 0n,
      sessionId: 0x55n,
      treeId: 0,
      status: 0,
    });
    // SESSION_SETUP response body is StructureSize(2) + SessionFlags(2) + SecBufOffset(2) + SecBufLen(2)
    const body = Buffer.from([0x09, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00]);
    ft.deliver(Buffer.concat([plain, body]));

    const got = await reqPromise;
    expect(got.header.command).toBe(SmbCommand.SESSION_SETUP);
  });

  it("accepts plaintext when encryption is NOT required", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    // No setEncryptionRequired — plaintext should be fine.
    conn.setEncryptor(makeEncryptor(makeKeys(), 0x55n));

    const reqPromise = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 0x55n });
    await new Promise((r) => setImmediate(r));

    const plain = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1,
      creditRequestResponse: 1,
      flags: 0x1,
      messageId: 0n,
      sessionId: 0x55n,
      treeId: 0,
      status: 0,
    });
    ft.deliver(Buffer.concat([plain, Buffer.alloc(0)]));

    const got = await reqPromise;
    expect(got.header.command).toBe(SmbCommand.READ);
  });
});

describe("Connection — combined signing+encryption", () => {
  it("under signingRequired=true + encryption installed: accepts encrypted-only frames", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const sessionId = 0xfeedfacen;
    const keys = makeKeys();
    const enc = makeEncryptor(keys, sessionId);
    conn.setEncryptor(enc);
    conn.setEncryptionRequired(true);
    conn.setSigningRequired(true);

    // Build a plaintext READ response (unsigned), then encrypt it for transport.
    const innerHeader = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1, creditRequestResponse: 1, flags: 0,
      messageId: 0n, sessionId, treeId: 0, status: 0,
    });
    const innerPdu = Buffer.concat([innerHeader, Buffer.alloc(8)]);
    // The connection decrypts inbound frames using keys.decryption.
    // So the "server" must encrypt with that same key to produce a frame the connection can decrypt.
    const serverKeys: EncryptionKeys = { ...keys, encryption: keys.decryption };
    const transportFrame = encryptMessage(innerPdu, serverKeys, sessionId, 1n);

    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId, encrypt: true });
    await new Promise((r) => setImmediate(r));
    ft.deliver(transportFrame);
    await expect(pending).resolves.toMatchObject({ header: { command: SmbCommand.READ } });
  });

  it("under signingRequired=true + encryption installed: rejects unsigned plaintext frames", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    conn.setEncryptor(makeEncryptor(makeKeys(), 1n));
    conn.setEncryptionRequired(true);
    conn.setSigningRequired(true);

    const header = encodeHeader({
      command: SmbCommand.READ,
      creditCharge: 1, creditRequestResponse: 1, flags: 0,
      messageId: 0n, sessionId: 1n, treeId: 0, status: 0,
    });
    const plaintextFrame = Buffer.concat([header, Buffer.alloc(8)]);

    const failures: unknown[] = [];
    const pending = conn.send(SmbCommand.READ, Buffer.alloc(0), { sessionId: 1n }).catch((e) => failures.push(e));
    await new Promise((r) => setImmediate(r));
    ft.deliver(plaintextFrame);
    await pending;
    expect(failures.length).toBeGreaterThan(0);
    // With both encryptionRequired and signingRequired set, the encryption check
    // in Connection.onMessage fires first (per source order). That's the message
    // we'll see — assert it directly rather than vaguely matching either guard.
    expect((failures[0] as Error).message).toMatch(/plaintext.*encryption/i);
  });
});
