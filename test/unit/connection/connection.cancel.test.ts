import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { sign } from "../../../src/connection/signing.js";
import { Dialect } from "../../../src/wire/commands.js";

describe("Connection.cancel", () => {
  it("emits a CANCEL frame referencing the supplied messageId", async () => {
    const ft = new FakeTransport();
    let lastSent: Buffer | null = null;
    ft.onSend((frame) => { lastSent = Buffer.from(frame.subarray(4)); });
    const conn = new Connection(ft);
    conn.cancel({ messageId: 0x42n });
    await new Promise((r) => setImmediate(r));
    expect(lastSent).not.toBeNull();
    // SMB2 header: command at offset 12 = CANCEL (0x000c)
    expect(lastSent!.readUInt16LE(12)).toBe(0x000c);
    expect(lastSent!.readBigUInt64LE(24)).toBe(0x42n);
    // ASYNC flag should NOT be set
    expect(lastSent!.readUInt32LE(16) & 0x02).toBe(0);
  });

  it("sets ASYNC flag and writes asyncId when given asyncId", async () => {
    const ft = new FakeTransport();
    let lastSent: Buffer | null = null;
    ft.onSend((frame) => { lastSent = Buffer.from(frame.subarray(4)); });
    const conn = new Connection(ft);
    conn.cancel({ asyncId: 0xdeadbeefn, messageId: 0x77n });
    await new Promise((r) => setImmediate(r));
    expect(lastSent).not.toBeNull();
    expect(lastSent!.readUInt32LE(16) & 0x02).toBe(0x02);
    expect(lastSent!.readBigUInt64LE(32)).toBe(0xdeadbeefn);
  });

  it("signs the CANCEL frame when a cancel signer is registered", async () => {
    const ft = new FakeTransport();
    let lastSent: Buffer | null = null;
    ft.onSend((frame) => { lastSent = Buffer.from(frame.subarray(4)); });
    const conn = new Connection(ft);
    const key = Buffer.alloc(16, 0xa5);
    const dialect = Dialect.SMB_3_1_1;
    conn.setCancelSigner((msg) => sign(msg, key, dialect));
    conn.cancel({ messageId: 0x42n, sessionId: 0x1n });
    await new Promise((r) => setImmediate(r));
    expect(lastSent).not.toBeNull();
    const sentMsg = lastSent!;
    // SIGNED flag (0x08) must be set in flags at offset 16
    const flags = sentMsg.readUInt32LE(16);
    expect(flags & 0x08).toBe(0x08);
    // Signature at bytes 48..64 must equal sign() over the frame with those bytes zeroed
    const probe = Buffer.from(sentMsg);
    probe.fill(0, 48, 64);
    const expectedSig = sign(probe, key, dialect);
    const actualSig = Buffer.from(sentMsg.subarray(48, 64));
    expect(actualSig).toEqual(expectedSig);
  });
});
