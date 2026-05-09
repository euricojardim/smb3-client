import type { Open } from "./open.js";
import {
  encodeChangeNotifyRequest,
  decodeChangeNotifyResponse,
  parseFileNotifyInformation,
  CompletionFilter,
  ChangeAction as CA,
} from "../wire/structs/changeNotify.js";
import { SmbCommand, NTStatus, isSuccess, statusName } from "../wire/commands.js";
import { SmbError } from "../errors.js";

export interface WatchOptions {
  recursive?: boolean;
  signal?: AbortSignal;
  completionFilter?: number;
}

export interface WatchEvent {
  action: "added" | "removed" | "modified" | "renamedOldName" | "renamedNewName";
  fileName: string;
}

const DEFAULT_FILTER =
  CompletionFilter.FILE_NAME |
  CompletionFilter.DIR_NAME |
  CompletionFilter.ATTRIBUTES |
  CompletionFilter.SIZE |
  CompletionFilter.LAST_WRITE |
  CompletionFilter.CREATION;

const ACTION_NAME: Record<number, WatchEvent["action"]> = {
  [CA.ADDED]: "added",
  [CA.REMOVED]: "removed",
  [CA.MODIFIED]: "modified",
  [CA.RENAMED_OLD_NAME]: "renamedOldName",
  [CA.RENAMED_NEW_NAME]: "renamedNewName",
};

export async function* watchOpen(open: Open, opts: WatchOptions = {}): AsyncGenerator<WatchEvent> {
  const filter = opts.completionFilter ?? DEFAULT_FILTER;
  const flags = opts.recursive ? 1 : 0; // SMB2_WATCH_TREE
  const conn = open.tree.conn;
  let aborted = false;
  let lastMessageId: bigint | null = null;

  if (opts.signal) {
    if (opts.signal.aborted) return;
    opts.signal.addEventListener("abort", () => {
      aborted = true;
      if (lastMessageId !== null) conn.cancel({ messageId: lastMessageId });
    }, { once: true });
  }

  while (!aborted) {
    const body = encodeChangeNotifyRequest({
      fileId: open.fileId,
      flags,
      outputBufferLength: 65536,
      completionFilter: filter,
    });
    const signing = open.tree.session.makeSigning();
    // Capture the message ID that will be assigned to this send before initiating the request.
    const capturedMessageId = (conn as unknown as { nextMessageId: bigint }).nextMessageId;
    let resp;
    try {
      const sent = conn.send(SmbCommand.CHANGE_NOTIFY, body, {
        sessionId: open.tree.session.sessionId,
        treeId: open.tree.treeId,
        ...(signing !== undefined ? { signing } : {}),
        creditCharge: 1,
      });
      lastMessageId = capturedMessageId;
      resp = await sent;
    } catch (err) {
      if (aborted) return;
      throw err;
    }
    if (resp.header.status === NTStatus.STATUS_CANCELLED) return;
    if (resp.header.status === NTStatus.STATUS_NOTIFY_CLEANUP) return;
    if (!isSuccess(resp.header.status)) {
      throw new SmbError({ status: resp.header.status, message: `CHANGE_NOTIFY failed: ${statusName(resp.header.status)}` });
    }
    const buf = decodeChangeNotifyResponse(resp.body, 64);
    if (buf.length === 0) continue;
    for (const it of parseFileNotifyInformation(buf)) {
      yield { action: ACTION_NAME[it.action] ?? "modified", fileName: it.fileName };
    }
    if (aborted) return;
  }
}
