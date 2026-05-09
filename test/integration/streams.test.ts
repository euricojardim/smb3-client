import { it, expect, beforeAll, afterAll } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { Client } from "../../src/index.js";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { randomBytes, createHash } from "node:crypto";

integrationDescribe("integration: streams", () => {
  const env = readIntegrationEnv()!;
  let client: Client;
  let base: string;

  beforeAll(async () => {
    base = `${env.share}/__node_smb3_streams`;
    client = new Client({
      host: env.host, port: env.port, domain: env.domain,
      username: env.username, password: env.password,
    });
    await client.connect();
    try { await client.rmdir(base); } catch { /* ignore */ }
    await client.mkdir(base);
  });
  afterAll(async () => {
    try { await client.rmdir(base); } catch { /* ignore */ }
    await client?.close();
  });

  it("streams 4 MiB up and back, byte-identical", { timeout: 60_000 }, async () => {
    const path = `${base}/big.bin`;
    const data = randomBytes(4 * 1024 * 1024);
    await pipeline(Readable.from(data), client.createWriteStream(path));
    const chunks: Buffer[] = [];
    for await (const c of client.createReadStream(path)) chunks.push(c as Buffer);
    const got = Buffer.concat(chunks);
    expect(got.length).toBe(data.length);
    const a = createHash("sha256").update(data).digest("hex");
    const b = createHash("sha256").update(got).digest("hex");
    expect(b).toBe(a);
    await client.rm(path);
  });
});
