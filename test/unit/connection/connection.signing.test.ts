import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { sign } from "../../../src/connection/signing.js";
import { Dialect, SmbCommand } from "../../../src/wire/commands.js";

describe("Connection.send signing", () => {
  it("zeros the signature field, computes signature over the full message, writes it back", async () => {
    const ft = new FakeTransport();
    const key = Buffer.alloc(16, 0xa5);
    let captured: Buffer | null = null;
    ft.onSend((frame) => {
      captured = Buffer.from(frame.subarray(4));
    });
    const conn = new Connection(ft);
    // Don't open(); manually inject negotiated state via test surface (added below).
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };

    const body = Buffer.from("0001", "hex"); // throwaway body
    void conn.send(SmbCommand.LOGOFF, body, {
      sessionId: 0x42n,
      signing: { sign: (m) => sign(m, key, Dialect.SMB_3_1_1) },
    });
    await new Promise((r) => setImmediate(r));
    expect(captured).not.toBeNull();
    const sentMsg = captured!;
    const sigField = Buffer.from(sentMsg.subarray(48, 64));
    // Recompute by zeroing signature
    const probe = Buffer.from(sentMsg);
    probe.fill(0, 48, 64);
    const expected = sign(probe, key, Dialect.SMB_3_1_1);
    expect(sigField).toEqual(expected);
    // SIGNED flag bit set
    const flags = sentMsg.readUInt32LE(16);
    expect(flags & 0x08).toBe(0x08);
  });
});
