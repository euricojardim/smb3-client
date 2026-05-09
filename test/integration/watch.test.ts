import { it, expect, beforeAll, afterAll } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { Client } from "../../src/index.js";

integrationDescribe("integration: watch", () => {
  const env = readIntegrationEnv()!;
  let client: Client;
  let base: string;

  beforeAll(async () => {
    base = `${env.share}/__node_smb3_watch`;
    client = new Client({
      host: env.host, port: env.port, domain: env.domain,
      username: env.username, password: env.password,
    });
    await client.connect();
    // Best-effort cleanup: remove any files left by a previous run, then rmdir.
    try {
      const entries = await client.readdir(base) as string[];
      for (const e of entries) {
        try { await client.rm(`${base}/${e}`); } catch { /* ignore */ }
      }
      await client.rmdir(base);
    } catch { /* ignore — dir may not exist */ }
    await client.mkdir(base);
  });
  afterAll(async () => {
    // Best-effort cleanup: remove any files left by the test, then rmdir.
    try {
      const entries = await client.readdir(base) as string[];
      for (const e of entries) {
        try { await client.rm(`${base}/${e}`); } catch { /* ignore */ }
      }
    } catch { /* ignore */ }
    try { await client.rmdir(base); } catch { /* ignore */ }
    await client?.close();
  });

  it("yields an 'added' event when a file appears", async () => {
    const ac = new AbortController();
    const events: Array<{ action: string; path: string }> = [];
    const consumer = (async () => {
      for await (const ev of client.watch(base, { recursive: false, signal: ac.signal })) {
        events.push(ev);
        if (events.length >= 1) ac.abort();
      }
    })();
    // Give the watcher a beat to register.
    await new Promise((r) => setTimeout(r, 250));
    await client.writeFile(`${base}/poke.txt`, Buffer.from("x"));
    await consumer;
    expect(events.some((e) => e.path.endsWith("poke.txt"))).toBe(true);
    await client.rm(`${base}/poke.txt`);
  });
});
