// Watch a directory for changes via CHANGE_NOTIFY, trigger an event by writing a file.
import { loadEnv, connectClient } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_watch`;
const trigger = `${dir}/poke.txt`;

try {
  console.log(`setting up ${dir} ...`);
  try {
    // Clean up any files left from a previous run before removing the dir.
    const leftover = await client.readdir(dir) as string[];
    for (const name of leftover) {
      try { await client.rm(`${dir}/${name}`); } catch { /* ignore */ }
    }
    await client.rmdir(dir);
  } catch { /* may not exist */ }
  await client.mkdir(dir);

  const ac = new AbortController();
  const events: Array<{ action: string; path: string }> = [];

  // Start the watch loop.
  const watchPromise = (async () => {
    for await (const ev of client.watch(dir, { recursive: false, signal: ac.signal })) {
      console.log(`  event: action=${ev.action}  path=${ev.path}`);
      events.push(ev);
      // Abort after the first event.
      ac.abort();
    }
  })();

  // Give the watcher time to register with the server.
  console.log("watch registered, waiting 500 ms before triggering ...");
  await new Promise((r) => setTimeout(r, 500));

  // Trigger the event.
  console.log(`writing ${trigger} to trigger CHANGE_NOTIFY ...`);
  await client.writeFile(trigger, Buffer.from("poke"));

  await watchPromise;

  if (events.length === 0) {
    throw new Error("no CHANGE_NOTIFY events received");
  }
  const matched = events.some((e) => e.path.includes("poke.txt"));
  if (!matched) {
    throw new Error(`expected an event path containing "poke.txt", got: ${JSON.stringify(events)}`);
  }
  console.log(`received ${events.length} event(s) — assertion passed`);

  console.log("cleaning up ...");
  try { await client.rm(trigger); } catch { /* may already be gone */ }
  await client.rmdir(dir);
} finally {
  await client.close();
}

console.log("done");
