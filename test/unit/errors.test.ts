import { describe, it, expect } from "vitest";
import { SmbError, SmbAuthError, SmbProtocolError, statusToCode } from "../../src/errors.js";
import { NTStatus } from "../../src/wire/commands.js";

describe("errors", () => {
  it("SmbError has status, statusName, code, message", () => {
    const e = new SmbError({
      status: NTStatus.STATUS_OBJECT_NAME_NOT_FOUND,
      message: "not found",
    });
    expect(e.status).toBe(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND);
    expect(e.statusName).toBe("STATUS_OBJECT_NAME_NOT_FOUND");
    expect(e.code).toBe("ENOENT");
    expect(e.name).toBe("SmbError");
  });

  it("statusToCode maps key NTSTATUS to fs codes", () => {
    expect(statusToCode(NTStatus.STATUS_ACCESS_DENIED)).toBe("EACCES");
    expect(statusToCode(NTStatus.STATUS_OBJECT_NAME_COLLISION)).toBe("EEXIST");
    expect(statusToCode(NTStatus.STATUS_DIRECTORY_NOT_EMPTY)).toBe("ENOTEMPTY");
    expect(statusToCode(NTStatus.STATUS_FILE_IS_A_DIRECTORY)).toBe("EISDIR");
    expect(statusToCode(NTStatus.STATUS_NOT_A_DIRECTORY)).toBe("ENOTDIR");
  });

  it("SmbAuthError and SmbProtocolError are subclasses with names", () => {
    const a = new SmbAuthError({ status: NTStatus.STATUS_LOGON_FAILURE, message: "x" });
    expect(a).toBeInstanceOf(SmbError);
    expect(a.name).toBe("SmbAuthError");
    const p = new SmbProtocolError({ status: 0, message: "signature mismatch" });
    expect(p.name).toBe("SmbProtocolError");
  });
});
