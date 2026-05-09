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
  signing?: "required" | "if-offered";
}
