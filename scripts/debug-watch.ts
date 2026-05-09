/**
 * debug-watch.ts — one-shot watcher diagnostic.
 *
 * Usage:
 *   set -a && . ./.env && set +a
 *   DEBUG_WATCH=1 npx tsx scripts/debug-watch.ts
 */

import { Client } from "../src/index.js";
import { Connection } from "../src/connection/connection.js";
import { decodeHeader } from "../src/wire/smb2-header.js";
import { SmbCommand, HeaderFlag, statusName } from "../src/wire/commands.js";

const DBG = !!process.env.DEBUG_WATCH;

function dbg(...args: unknown[]) {
  if (DBG) console.log("[DEBUG-WATCH]", ...args);
}

// Monkey-patch Connection to add wire-level logging.
if (DBG) {
  const proto = Connection.prototype as unknown as Record<string, unknown>;

  const origSend = proto["send"] as (
    command: number,
    body: Buffer,
    opts?: unknown,
  ) => Promise<{ header: unknown; body: Buffer }>;

  proto["send"] = async function (
    this: Connection & { nextMessageId: bigint },
    command: number,
    body: Buffer,
    opts?: unknown,
  ) {
    const msgId = this.nextMessageId; // peek BEFORE send increments it
    const cmdName =
      Object.entries(SmbCommand).find(([, v]) => v === command)?.[0] ?? `0x${command.toString(16)}`;
    dbg(`→ SEND  cmd=${cmdName} msgId=${msgId}`);
    const result = await origSend.call(this, command, body, opts);
    const h = result.header as { status: number; messageId: bigint; asyncId?: bigint; flags: number };
    const isAsync = (h.flags & HeaderFlag.ASYNC_COMMAND) !== 0;
    dbg(
      `← RECV  cmd=${cmdName} msgId=${h.messageId} asyncId=${h.asyncId ?? "–"}` +
        ` status=${statusName(h.status)} ASYNC=${isAsync}`,
    );
    return result;
  };

  const origOnMessage = proto["onMessage"] as (msg: Buffer) => void;
  proto["onMessage"] = function (this: Connection, msg: Buffer) {
    try {
      const { header, isAsync } = decodeHeader(msg);
      const cmdName =
        Object.entries(SmbCommand).find(([, v]) => v === header.command)?.[0] ??
        `0x${header.command.toString(16)}`;
      dbg(
        `   onMessage cmd=${cmdName} msgId=${header.messageId} asyncId=${header.asyncId ?? "–"}` +
          ` status=${statusName(header.status)} ASYNC=${isAsync}`,
      );
    } catch {
      dbg("   onMessage: failed to decode header");
    }
    origOnMessage.call(this, msg);
  };
}

const host = process.env.SMB_TEST_HOST!;
const port = Number(process.env.SMB_TEST_PORT ?? 445);
const domain = process.env.SMB_TEST_DOMAIN ?? "";
const username = process.env.SMB_TEST_USERNAME!;
const password = process.env.SMB_TEST_PASSWORD!;
const share = process.env.SMB_TEST_SHARE!;

const base = `${share}/__node_smb3_watch_debug`;

const client = new Client({ host, port, domain, username, password });
await client.connect();
console.log("Connected.");

// Ensure watch directory exists.
try {
  await client.mkdir(base);
  console.log(`mkdir ${base} → ok`);
} catch (err) {
  const msg = (err as Error).message;
  if (msg.includes("OBJECT_NAME_COLLISION") || msg.includes("STATUS_OBJECT_NAME_COLLISION")) {
    console.log(`mkdir ${base} → already exists (ok)`);
  } else {
    console.error(`mkdir ${base} → ERROR:`, msg);
    process.exit(1);
  }
}

// Abort controller — will fire after first event (or after 5s).
const ac = new AbortController();

// Start watcher.
const events: Array<{ action: string; path: string }> = [];
const watchPromise = (async () => {
  console.log("Starting watcher …");
  for await (const ev of client.watch(base, { recursive: false, signal: ac.signal })) {
    console.log("EVENT:", ev);
    events.push(ev);
    if (events.length >= 1) {
      console.log("Got first event — aborting watcher.");
      ac.abort();
    }
  }
  console.log("Watcher done.");
})();

// Give the CHANGE_NOTIFY time to reach the server.
await new Promise((r) => setTimeout(r, 500));

// Write a file to trigger the change notification.
const poke = `${base}/poke_${Date.now()}.txt`;
console.log(`Writing ${poke} …`);
await client.writeFile(poke, Buffer.from("debug-watch"));
console.log("writeFile done.");

// Wait up to 5 seconds for an event.
const timeout = new Promise<void>((r) => setTimeout(() => { r(); }, 5000));
await Promise.race([
  watchPromise,
  timeout.then(() => {
    if (events.length === 0) {
      console.error("TIMEOUT — no event received in 5s. Aborting watcher.");
      ac.abort();
    }
  }),
]);

// Cleanup.
try { await client.rm(poke); } catch { /* ignore */ }
try { await client.rmdir(base); } catch { /* ignore */ }
await client.close();

console.log("Done. Events received:", events.length);
if (events.length === 0) {
  console.error("BUG: no watch event was delivered.");
  process.exit(1);
} else {
  console.log("OK: watch event delivered successfully.");
}
