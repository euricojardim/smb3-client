import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";

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
});
