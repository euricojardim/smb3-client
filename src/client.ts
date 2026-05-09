import { TcpTransport } from "./transport/socket.js";
import { Connection } from "./connection/connection.js";
import { Session } from "./session/session.js";
import { Tree } from "./tree/tree.js";
import { Open } from "./open/open.js";
import { readAll } from "./open/read.js";
import { writeAll } from "./open/write.js";
import { metaToStat } from "./open/query.js";
import { readdirAll } from "./open/readdir.js";
import {
  CreateDisposition,
  CreateOptions,
  FileAccess,
  FileAttribute,
  ShareAccess,
} from "./wire/structs/create.js";
import { splitSharePath, toSmbPath } from "./paths.js";
import type { ClientOptions, Dirent, FileStat } from "./types.js";

export class Client {
  private conn: Connection | null = null;
  private session: Session | null = null;
  private trees = new Map<string, Tree>();
  private state: "idle" | "connected" | "closed" = "idle";

  constructor(private readonly opts: ClientOptions) {}

  async connect(): Promise<void> {
    if (this.state !== "idle") throw new Error(`Client.connect: state=${this.state}`);
    const transport = await TcpTransport.connect(this.opts.host, this.opts.port ?? 445, {
      timeoutMs: this.opts.connectTimeout ?? 10_000,
    });
    this.conn = new Connection(transport);
    await this.conn.open();
    this.session = new Session(this.conn, {
      username: this.opts.username,
      password: this.opts.password,
      domain: this.opts.domain ?? "",
    });
    await this.session.setup();
    this.state = "connected";
  }

  private async treeFor(share: string): Promise<Tree> {
    if (!this.conn || !this.session) throw new Error("not connected");
    let t = this.trees.get(share);
    if (t) return t;
    const sharePath = `\\\\${this.opts.host}\\${share}`;
    t = await Tree.connect(this.conn, this.session, sharePath);
    this.trees.set(share, t);
    return t;
  }

  async readFile(path: string): Promise<Buffer>;
  async readFile(path: string, encoding: BufferEncoding): Promise<string>;
  async readFile(path: string, encoding?: BufferEncoding): Promise<Buffer | string> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    return Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: CreateOptions.NON_DIRECTORY_FILE,
      fileAttributes: 0,
    }, async (open) => {
      const buf = await readAll(open, open.meta.endOfFile);
      return encoding ? buf.toString(encoding) : buf;
    });
  }

  async writeFile(path: string, data: Buffer | string, encoding: BufferEncoding = "utf8"): Promise<void> {
    const buf = typeof data === "string" ? Buffer.from(data, encoding) : data;
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    await Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.GENERIC_WRITE | FileAccess.FILE_READ_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OVERWRITE_IF,
      createOptions: CreateOptions.NON_DIRECTORY_FILE,
      fileAttributes: 0,
    }, async (open) => writeAll(open, 0n, buf));
  }

  async readdir(path: string): Promise<string[]>;
  async readdir(path: string, opts: { withFileTypes: true }): Promise<Dirent[]>;
  async readdir(path: string, opts?: { withFileTypes?: boolean }): Promise<string[] | Dirent[]> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    return Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: 1, // DIRECTORY_FILE
      fileAttributes: 0,
    }, async (open) => {
      const entries = await readdirAll(open);
      if (!opts?.withFileTypes) return entries.map((e) => e.fileName);
      return entries.map((e) => {
        const isDir = (e.fileAttributes & FileAttribute.DIRECTORY) !== 0;
        return {
          name: e.fileName,
          isFile: () => !isDir,
          isDirectory: () => isDir,
        } satisfies Dirent;
      });
    });
  }

  async stat(path: string): Promise<FileStat> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    return Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.FILE_READ_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: 0,
      fileAttributes: 0,
    }, async (open) => metaToStat(open.meta));
  }

  async mkdir(path: string): Promise<void> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    await Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.FILE_READ_ATTRIBUTES | FileAccess.FILE_WRITE_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.CREATE,
      createOptions: 1, // DIRECTORY_FILE
      fileAttributes: 0,
    }, async () => undefined);
  }

  async close(): Promise<void> {
    if (this.state === "closed") return;
    this.state = "closed";
    for (const t of this.trees.values()) {
      try { await t.disconnect(); } catch { /* ignore */ }
    }
    this.trees.clear();
    if (this.session) {
      try { await this.session.close(); } catch { /* ignore */ }
    }
    this.conn?.close();
  }
}
