import { it, expect, beforeAll, afterAll } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { Client } from "../../src/index.js";

integrationDescribe("integration: readFile/stat", () => {
  const env = readIntegrationEnv()!;
  let client: Client;

  beforeAll(async () => {
    client = new Client({
      host: env.host,
      port: env.port,
      domain: env.domain,
      username: env.username,
      password: env.password,
    });
    await client.connect();
  });

  afterAll(async () => {
    await client?.close();
  });

  it("stats a file that exists", async () => {
    // Requires SMB_TEST_SMALL_FILE pointing to "share/path/to/file.txt"
    const target = process.env.SMB_TEST_SMALL_FILE;
    if (!target) return;
    const s = await client.stat(target);
    expect(s.isFile).toBe(true);
    expect(s.size).toBeGreaterThanOrEqual(0);
  });

  it("readFile returns the bytes", async () => {
    const target = process.env.SMB_TEST_SMALL_FILE;
    if (!target) return;
    const buf = await client.readFile(target);
    expect(Buffer.isBuffer(buf)).toBe(true);
  });
});
