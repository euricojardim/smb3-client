export interface FileStat {
  size: number;
  isFile: boolean;
  isDirectory: boolean;
  attributes: number;
  readonly: boolean;
  hidden: boolean;
  system: boolean;
  archive: boolean;
  ctime: Date;
  atime: Date;
  mtime: Date;
  changeTime: Date;
}

export interface Dirent {
  name: string;
  isFile: () => boolean;
  isDirectory: () => boolean;
  /** Size in bytes (0 for directories), from the directory listing itself. */
  size: number;
  /** Last write time, from the directory listing itself. */
  mtime: Date;
}

export interface ReadStreamOptions {
  /** Byte offset to start reading from (default 0). */
  start?: number;
}

export interface WriteStreamOptions {
  /**
   * Byte offset to start writing at (default 0). With 0 the file is created or
   * truncated; with a positive offset an existing file is kept and written from
   * there (resuming an interrupted upload).
   */
  start?: number;
}

export interface ShareInfo {
  name: string;
  type: "disk" | "ipc" | "print" | "special";
  comment: string;
}

export type ChangeAction =
  | "added"
  | "removed"
  | "modified"
  | "renamedOldName"
  | "renamedNewName";

export interface ChangeEvent {
  action: ChangeAction;
  path: string;
}

export interface ClientOptions {
  host: string;
  port?: number;
  domain?: string;
  username: string;
  password: string;
  connectTimeout?: number;
  requestTimeout?: number;
  signing?: "disabled" | "if-offered" | "required";
  encryption?: "required" | "if-offered" | "disabled";
}
