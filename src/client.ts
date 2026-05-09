import { Readable, Writable } from "node:stream";
import { TcpTransport } from "./transport/socket.js";
import { Connection } from "./connection/connection.js";
import { Session } from "./session/session.js";
import { Tree } from "./tree/tree.js";
import { Open } from "./open/open.js";
import { readAll } from "./open/read.js";
import { writeAll } from "./open/write.js";
import { metaToStat } from "./open/query.js";
import { readdirAll } from "./open/readdir.js";
import { createReadStream as openCreateReadStream } from "./open/readStream.js";
import { createWriteStream as openCreateWriteStream } from "./open/writeStream.js";
import { watchOpen } from "./open/changeNotify.js";
import {
  CreateDisposition,
  CreateOptions,
  FileAccess,
  FileAttribute,
  ShareAccess,
} from "./wire/structs/create.js";
import { splitSharePath, toSmbPath } from "./paths.js";
import type { ClientOptions, Dirent, FileStat, ChangeEvent, ShareInfo } from "./types.js";
import { encodeSetInfoRequest, encodeFileRenameInformation } from "./wire/structs/setInfo.js";
import { InfoType, FileInformationClass } from "./wire/structs/queryInfo.js";
import { SmbCommand, isSuccess, statusName } from "./wire/commands.js";
import { SmbError } from "./errors.js";
import { encodeIoctlRequest, decodeIoctlResponse } from "./wire/structs/ioctl.js";
import {
  encodeBindRequest,
  encodeRequest as rpcRequest,
  parseResponse as rpcResponse,
  encodeNetrShareEnumRequest,
  parseNetrShareEnumResponse,
  SRVSVC_UUID,
  SRVSVC_MAJOR,
  SRVSVC_MINOR,
} from "./rpc/srvsvc.js";

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

  async rm(path: string): Promise<void> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    await Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.DELETE,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: CreateOptions.NON_DIRECTORY_FILE | CreateOptions.DELETE_ON_CLOSE,
      fileAttributes: 0,
    }, async () => undefined);
  }

  async rmdir(path: string): Promise<void> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    await Open.withOpen(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.DELETE,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: CreateOptions.DIRECTORY_FILE | CreateOptions.DELETE_ON_CLOSE,
      fileAttributes: 0,
    }, async () => undefined);
  }

  async rename(from: string, to: string): Promise<void> {
    const f = splitSharePath(from);
    const t = splitSharePath(to);
    if (f.share !== t.share) {
      throw new SmbError({ status: 0, message: "rename across shares is not supported" });
    }
    const tree = await this.treeFor(f.share);
    await Open.withOpen(tree, {
      filename: toSmbPath(f.rest),
      desiredAccess: FileAccess.DELETE | FileAccess.FILE_READ_ATTRIBUTES,
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: 0,
      fileAttributes: 0,
    }, async (open) => {
      const inner = encodeFileRenameInformation({
        replaceIfExists: false,
        fileName: toSmbPath(t.rest),
      });
      const body = encodeSetInfoRequest({
        infoType: InfoType.FILE,
        fileInformationClass: FileInformationClass.FileRenameInformation,
        fileId: open.fileId,
        buffer: inner,
      });
      const signing = tree.session.makeSigning();
      const resp = await tree.conn.send(SmbCommand.SET_INFO, body, {
        sessionId: tree.session.sessionId,
        treeId: tree.treeId,
        ...(signing !== undefined ? { signing } : {}),
        creditCharge: 1,
      });
      if (!isSuccess(resp.header.status)) {
        throw new SmbError({
          status: resp.header.status,
          message: `SET_INFO rename failed: ${statusName(resp.header.status)}`,
        });
      }
    });
  }

  async *watch(path: string, opts: { recursive?: boolean; signal?: AbortSignal } = {}): AsyncGenerator<ChangeEvent> {
    const { share, rest } = splitSharePath(path);
    const tree = await this.treeFor(share);
    const open = await Open.create(tree, {
      filename: toSmbPath(rest),
      desiredAccess: FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES, // FILE_LIST_DIRECTORY = FILE_READ_DATA
      shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
      createDisposition: CreateDisposition.OPEN,
      createOptions: 1, // DIRECTORY_FILE
      fileAttributes: 0,
    });
    try {
      for await (const ev of watchOpen(open, opts)) {
        const fullPath = `${share}/${toSmbPath(rest).replace(/\\/g, "/")}/${ev.fileName.replace(/\\/g, "/")}`
          .replace(/\/+/g, "/");
        yield { action: ev.action, path: fullPath } satisfies ChangeEvent;
      }
    } finally {
      try { await open.close(); } catch { /* ignore */ }
    }
  }

  createReadStream(path: string): Readable {
    const out = new Readable({ read() {} });
    void this._beginReadStream(path, out);
    return out;
  }

  private async _beginReadStream(path: string, out: Readable): Promise<void> {
    try {
      const { share, rest } = splitSharePath(path);
      const tree = await this.treeFor(share);
      const open = await Open.create(tree, {
        filename: toSmbPath(rest),
        desiredAccess: FileAccess.FILE_READ_DATA | FileAccess.FILE_READ_ATTRIBUTES,
        shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
        createDisposition: CreateDisposition.OPEN,
        createOptions: CreateOptions.NON_DIRECTORY_FILE,
        fileAttributes: 0,
      });
      const inner = openCreateReadStream(open);
      inner.on("data", (chunk) => { if (!out.push(chunk)) inner.pause(); });
      out.on("drain" as never, () => inner.resume());
      inner.on("end", async () => { try { await open.close(); } catch { /* ignore */ } out.push(null); });
      inner.on("error", (e) => { open.close().catch(() => undefined); out.destroy(e); });
      out.on("close", () => inner.destroy());
    } catch (err) {
      out.destroy(err as Error);
    }
  }

  createWriteStream(path: string): Writable {
    const proxy = new Writable({
      write(chunk, _enc, cb) {
        this.emit("__chunk" as never, chunk, cb);
      },
      final(cb) {
        this.emit("__final" as never, cb);
      },
    });
    void this._beginWriteStream(path, proxy);
    return proxy;
  }

  private async _beginWriteStream(path: string, proxy: Writable): Promise<void> {
    try {
      const { share, rest } = splitSharePath(path);
      const tree = await this.treeFor(share);
      const open = await Open.create(tree, {
        filename: toSmbPath(rest),
        desiredAccess: FileAccess.GENERIC_WRITE | FileAccess.FILE_READ_ATTRIBUTES,
        shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
        createDisposition: CreateDisposition.OVERWRITE_IF,
        createOptions: CreateOptions.NON_DIRECTORY_FILE,
        fileAttributes: 0,
      });
      const inner = openCreateWriteStream(open);
      proxy.on("__chunk" as never, (chunk: Buffer, cb: (err?: Error) => void) => {
        inner.write(chunk, (err) => cb(err ?? undefined));
      });
      proxy.on("__final" as never, (cb: (err?: Error) => void) => {
        inner.end(() => cb());
      });
      inner.on("error", (e) => proxy.destroy(e));
    } catch (err) {
      proxy.destroy(err as Error);
    }
  }

  async listShares(): Promise<ShareInfo[]> {
    if (!this.conn || !this.session) throw new Error("not connected");
    const ipcPath = `\\\\${this.opts.host}\\IPC$`;
    const ipc = await Tree.connect(this.conn, this.session, ipcPath);
    try {
      return await Open.withOpen(ipc, {
        filename: "srvsvc",
        desiredAccess: FileAccess.GENERIC_READ | FileAccess.GENERIC_WRITE | FileAccess.FILE_READ_ATTRIBUTES,
        shareAccess: ShareAccess.READ | ShareAccess.WRITE | ShareAccess.DELETE,
        createDisposition: CreateDisposition.OPEN,
        createOptions: 0,
        fileAttributes: 0,
      }, async (open) => {
        // Bind
        const bind = encodeBindRequest({ callId: 1, abstractUuid: SRVSVC_UUID, abstractMajor: SRVSVC_MAJOR, abstractMinor: SRVSVC_MINOR });
        await this._pipeTransceive(open, bind);
        // Request: NetrShareEnum (opnum 15)
        const stub = encodeNetrShareEnumRequest({
          serverName: `\\\\${this.opts.host}`,
          infoLevel: 1,
          preferredMaximumLength: 0xffffffff,
        });
        const req = rpcRequest({ callId: 2, opnum: 15, contextId: 0, stub });
        const respFrame = await this._pipeTransceive(open, req);
        const respStub = rpcResponse(respFrame);
        if (!respStub) return [];
        const parsed = parseNetrShareEnumResponse(respStub);
        return parsed.entries.map((e) => ({
          name: e.name,
          type: ((e.type & 0xff) === 0 ? "disk" : (e.type & 0xff) === 1 ? "print" : (e.type & 0xff) === 3 ? "ipc" : "special") as ShareInfo["type"],
          comment: e.comment,
        }));
      });
    } finally {
      await ipc.disconnect().catch(() => undefined);
    }
  }

  private async _pipeTransceive(open: Open, payload: Buffer): Promise<Buffer> {
    const FSCTL_PIPE_TRANSCEIVE = 0x0011c017;
    const body = encodeIoctlRequest({
      ctlCode: FSCTL_PIPE_TRANSCEIVE,
      fileId: open.fileId,
      input: payload,
      maxOutputResponse: 1024 * 1024,
      flags: 1, // SMB2_0_IOCTL_IS_FSCTL
    });
    const signing = open.tree.session.makeSigning();
    const resp = await open.tree.conn.send(SmbCommand.IOCTL, body, {
      sessionId: open.tree.session.sessionId,
      treeId: open.tree.treeId,
      ...(signing !== undefined ? { signing } : {}),
      creditCharge: 1,
    });
    return decodeIoctlResponse(resp.body, 64);
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
