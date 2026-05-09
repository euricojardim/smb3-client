import { NTStatus, statusName } from "./wire/commands.js";

export type FsCode =
  | "ENOENT"
  | "EEXIST"
  | "EACCES"
  | "EBUSY"
  | "ENOTDIR"
  | "EISDIR"
  | "ENOTEMPTY"
  | "ENOSPC"
  | "ENXIO"
  | "EINVAL"
  | "ECONNRESET"
  | "ETIMEDOUT"
  | "ECANCELED";

const STATUS_TO_CODE: Record<number, FsCode> = {
  [NTStatus.STATUS_OBJECT_NAME_NOT_FOUND]: "ENOENT",
  [NTStatus.STATUS_OBJECT_PATH_NOT_FOUND]: "ENOENT",
  [NTStatus.STATUS_NO_SUCH_FILE]: "ENOENT",
  [NTStatus.STATUS_OBJECT_NAME_COLLISION]: "EEXIST",
  [NTStatus.STATUS_ACCESS_DENIED]: "EACCES",
  [NTStatus.STATUS_PRIVILEGE_NOT_HELD]: "EACCES",
  [NTStatus.STATUS_SHARING_VIOLATION]: "EBUSY",
  [NTStatus.STATUS_FILE_LOCK_CONFLICT]: "EBUSY",
  [NTStatus.STATUS_NOT_A_DIRECTORY]: "ENOTDIR",
  [NTStatus.STATUS_FILE_IS_A_DIRECTORY]: "EISDIR",
  [NTStatus.STATUS_DIRECTORY_NOT_EMPTY]: "ENOTEMPTY",
  [NTStatus.STATUS_DISK_FULL]: "ENOSPC",
  [NTStatus.STATUS_NETWORK_NAME_DELETED]: "ENXIO",
  [NTStatus.STATUS_BAD_NETWORK_NAME]: "ENXIO",
  [NTStatus.STATUS_INVALID_PARAMETER]: "EINVAL",
  [NTStatus.STATUS_CANCELLED]: "ECANCELED",
};

export function statusToCode(status: number): FsCode | undefined {
  return STATUS_TO_CODE[status];
}

export interface SmbErrorOptions {
  status: number;
  message: string;
  cause?: unknown;
}

export class SmbError extends Error {
  readonly status: number;
  readonly statusName: string;
  readonly code: FsCode | undefined;

  constructor(opts: SmbErrorOptions) {
    super(opts.message, opts.cause === undefined ? undefined : { cause: opts.cause });
    this.name = "SmbError";
    this.status = opts.status;
    this.statusName = statusName(opts.status);
    this.code = statusToCode(opts.status);
  }
}

export class SmbAuthError extends SmbError {
  constructor(opts: SmbErrorOptions) {
    super(opts);
    this.name = "SmbAuthError";
  }
}

export class SmbProtocolError extends SmbError {
  constructor(opts: SmbErrorOptions) {
    super(opts);
    this.name = "SmbProtocolError";
  }
}
