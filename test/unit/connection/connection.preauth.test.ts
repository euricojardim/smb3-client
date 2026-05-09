import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { encodeHeader } from "../../../src/wire/smb2-header.js";
import { SmbCommand, NTStatus, HeaderFlag } from "../../../src/wire/commands.js";

function fakeServerFrame(command: number, messageId: bigint, status: number): Buffer {
  const hdr = encodeHeader({
    command,
    creditCharge: 1,
    creditRequestResponse: 1,
    flags: HeaderFlag.SERVER_TO_REDIR,
    messageId,
    sessionId: 0n,
    treeId: 0,
    status,
  });
  // 4-byte trailing body (StructureSize-only placeholder)
  return Buffer.concat([hdr, Buffer.from([0x09, 0, 0, 0])]);
}

describe("Connection preauth update guard", () => {
  it("includes NEGOTIATE responses and SESSION_SETUP CHALLENGE responses, but excludes SESSION_SETUP SUCCESS responses", () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    const initial = conn.preauthDigest();

    // NEGOTIATE response — should update the preauth hash
    ft.deliver(fakeServerFrame(SmbCommand.NEGOTIATE, 0n, 0));
    return new Promise<void>((resolve) => {
      setImmediate(() => {
        const afterNeg = conn.preauthDigest();
        expect(afterNeg.equals(initial)).toBe(false);

        // SESSION_SETUP STATUS_MORE_PROCESSING_REQUIRED (CHALLENGE) — should update
        ft.deliver(fakeServerFrame(SmbCommand.SESSION_SETUP, 1n, NTStatus.STATUS_MORE_PROCESSING_REQUIRED));
        setImmediate(() => {
          const afterChallenge = conn.preauthDigest();
          expect(afterChallenge.equals(afterNeg)).toBe(false);

          // SESSION_SETUP STATUS_SUCCESS — should NOT update
          ft.deliver(fakeServerFrame(SmbCommand.SESSION_SETUP, 2n, 0));
          setImmediate(() => {
            const afterSuccess = conn.preauthDigest();
            expect(afterSuccess.equals(afterChallenge)).toBe(true);
            resolve();
          });
        });
      });
    });
  });
});
