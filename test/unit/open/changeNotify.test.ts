import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Tree } from "../../../src/tree/tree.js";
import { Open } from "../../../src/open/open.js";
import { watchOpen } from "../../../src/open/changeNotify.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { Writer } from "../../../src/wire/buffer.js";
import { Dialect, NTStatus, SmbCommand, HeaderFlag } from "../../../src/wire/commands.js";

function fniEntry(action: number, name: string, isLast: boolean): Buffer {
  const nb = Buffer.from(name, "utf16le");
  const recSize = 12 + nb.length;
  const padded = (recSize + 3) & ~3;
  const w = new Writer();
  w.u32(isLast ? 0 : padded); w.u32(action); w.u32(nb.length); w.bytes(nb);
  w.pad(padded - recSize);
  return w.buffer();
}

function cnFinalFrame(messageId: bigint, asyncId: bigint, payload: Buffer): Buffer {
  const w = new Writer();
  w.u16(9); w.u16(64 + 8); w.u32(payload.length); w.bytes(payload);
  const hdr = encodeHeader({
    command: SmbCommand.CHANGE_NOTIFY,
    creditCharge: 1, creditRequestResponse: 1,
    flags: HeaderFlag.SERVER_TO_REDIR | HeaderFlag.ASYNC_COMMAND,
    messageId, asyncId, sessionId: 0xabcdn, status: 0,
  });
  return Buffer.concat([hdr, w.buffer()]);
}

function cnPendingFrame(messageId: bigint, asyncId: bigint): Buffer {
  const hdr = encodeHeader({
    command: SmbCommand.CHANGE_NOTIFY,
    creditCharge: 1, creditRequestResponse: 1,
    flags: HeaderFlag.SERVER_TO_REDIR | HeaderFlag.ASYNC_COMMAND,
    messageId, asyncId, sessionId: 0xabcdn, status: NTStatus.STATUS_PENDING,
  });
  return Buffer.concat([hdr, Buffer.from([0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])]);
}

describe("watchOpen", () => {
  it("yields events from pending+final notify cycles", async () => {
    const ft = new FakeTransport();
    let issued = 0;
    ft.onSend((frame) => {
      const smb = frame.subarray(4);
      if (smb.readUInt16LE(12) !== SmbCommand.CHANGE_NOTIFY) return;
      const messageId = smb.readBigUInt64LE(24);
      const asyncId = BigInt(0x1000 + issued);
      issued++;
      // Interim PENDING then a final response with one entry
      ft.deliver(cnPendingFrame(messageId, asyncId));
      const payload = fniEntry(1, "a.txt", true);
      setImmediate(() => ft.deliver(cnFinalFrame(messageId, asyncId, payload)));
    });
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const tree = Object.assign(Object.create(Tree.prototype), {
      conn, session: { sessionId: 0xabcdn, makeSigning: () => undefined },
      treeId: 0x42, shareType: "disk", path: "x", maximalAccess: 0,
    }) as Tree;
    const open = new (Open as unknown as { new (...a: unknown[]): Open })(tree, Buffer.alloc(16, 0xfe), {} as never);
    const ac = new AbortController();
    const events: { action: string; fileName: string }[] = [];
    let count = 0;
    for await (const ev of watchOpen(open, { recursive: true, signal: ac.signal })) {
      events.push(ev);
      if (++count >= 1) ac.abort();
    }
    expect(events.length).toBeGreaterThanOrEqual(1);
    expect(events[0]!.fileName).toBe("a.txt");
  });
});
