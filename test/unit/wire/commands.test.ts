import { describe, it, expect } from "vitest";
import {
  SmbCommand,
  Dialect,
  HeaderFlag,
  NTStatus,
  isSuccess,
  isPending,
  statusName,
} from "../../../src/wire/commands.js";

describe("commands", () => {
  it("opcodes match spec", () => {
    expect(SmbCommand.NEGOTIATE).toBe(0x0000);
    expect(SmbCommand.SESSION_SETUP).toBe(0x0001);
    expect(SmbCommand.TREE_CONNECT).toBe(0x0003);
    expect(SmbCommand.CREATE).toBe(0x0005);
    expect(SmbCommand.READ).toBe(0x0008);
    expect(SmbCommand.QUERY_DIRECTORY).toBe(0x000e);
    expect(SmbCommand.CHANGE_NOTIFY).toBe(0x000f);
  });

  it("dialect codes", () => {
    expect(Dialect.SMB_2_1_0).toBe(0x0210);
    expect(Dialect.SMB_3_0_0).toBe(0x0300);
    expect(Dialect.SMB_3_0_2).toBe(0x0302);
    expect(Dialect.SMB_3_1_1).toBe(0x0311);
  });

  it("header flag bits", () => {
    expect(HeaderFlag.SIGNED).toBe(0x00000008);
    expect(HeaderFlag.ASYNC_COMMAND).toBe(0x00000002);
    expect(HeaderFlag.SERVER_TO_REDIR).toBe(0x00000001);
  });

  it("NTSTATUS helpers", () => {
    expect(isSuccess(0)).toBe(true);
    expect(isSuccess(NTStatus.STATUS_PENDING)).toBe(false);
    expect(isPending(NTStatus.STATUS_PENDING)).toBe(true);
    expect(statusName(NTStatus.STATUS_OBJECT_NAME_NOT_FOUND)).toBe("STATUS_OBJECT_NAME_NOT_FOUND");
    expect(statusName(0xdeadbeef)).toBe("0xDEADBEEF");
  });
});
