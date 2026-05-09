// Watch continuously via CHANGE_NOTIFY and print every event until Ctrl+C.
import { loadEnv, connectClient, ensureCleanDir, removeDirRecursively } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_watch_continuously`;
const trigger = `${dir}/poke.txt`;

const ac = new AbortController();
let stopping = false;
let eventCount = 0;
const QUIET_MS = 1200;
const STABLE_SAMPLE_MS = 400;

type CompletionState = {
  timer: ReturnType<typeof setTimeout>;
  lastAction: string;
  lastEventIso: string;
};

const completionByPath = new Map<string, CompletionState>();

const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

const armCompletionCheck = (fullPath: string, relPath: string, lastAction: string, lastEventIso: string) => {
  const prev = completionByPath.get(fullPath);
  if (prev) clearTimeout(prev.timer);

  const timer = setTimeout(() => {
    void (async () => {
      try {
        const s1 = await client.stat(fullPath);
        await wait(STABLE_SAMPLE_MS);
        const s2 = await client.stat(fullPath);
        if (s1.size === s2.size && s1.mtime.getTime() === s2.mtime.getTime()) {
          console.log(
            `[copy-complete] relPath=${relPath} fullPath=${fullPath} size=${s2.size} mtime=${s2.mtime.toISOString()} quietMs=${QUIET_MS} lastAction=${lastAction} lastEvent=${lastEventIso}`,
          );
        }
      } catch {
        // The file may have been moved/removed or be inaccessible at this point.
      } finally {
        completionByPath.delete(fullPath);
      }
    })();
  }, QUIET_MS);

  completionByPath.set(fullPath, { timer, lastAction, lastEventIso });
};

const stop = () => {
  if (stopping) return;
  stopping = true;
  ac.abort();
};

process.once("SIGINT", stop);
process.once("SIGTERM", stop);

try {
  console.log(`setting up ${dir} ...`);
  await ensureCleanDir(client, dir);

  console.log("watch registered, waiting 500 ms before triggering test file ...");

  const watchPromise = (async () => {
    for await (const ev of client.watch(dir, { recursive: false, signal: ac.signal })) {
      eventCount += 1;
      const now = new Date();
      const whenIso = now.toISOString();
      const whenEpochMs = now.getTime();
      const relPath = ev.path.startsWith(`${dir}/`) ? ev.path.slice(dir.length + 1) : ev.path;
      console.log(
        `[event #${eventCount}] iso=${whenIso} epochMs=${whenEpochMs} action=${ev.action} relPath=${relPath} fullPath=${ev.path}`,
      );
      console.log(`  payload=${JSON.stringify(ev)}`);

      // Heuristic: copy is "finished" when writes go quiet for a bit and metadata stabilizes.
      if (ev.action === "added" || ev.action === "modified" || ev.action === "renamedNewName") {
        armCompletionCheck(ev.path, relPath, ev.action, whenIso);
      }
    }
  })();

  await new Promise((r) => setTimeout(r, 500));
  console.log(`writing ${trigger} ...`);
  await client.writeFile(trigger, Buffer.from(`poke ${new Date().toISOString()}`));
  console.log("watching continuously; press Ctrl+C to stop");

  await watchPromise;
} finally {
  for (const state of completionByPath.values()) {
    clearTimeout(state.timer);
  }
  completionByPath.clear();
  process.off("SIGINT", stop);
  process.off("SIGTERM", stop);
  console.log("cleaning up ...");
  await removeDirRecursively(client, dir);
  await client.close();
}

console.log("done");
