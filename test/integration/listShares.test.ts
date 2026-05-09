import { it, expect, beforeAll, afterAll } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { Client } from "../../src/index.js";

integrationDescribe("integration: listShares", () => {
  const env = readIntegrationEnv()!;
  let client: Client;
  beforeAll(async () => {
    client = new Client({
      host: env.host, port: env.port, domain: env.domain,
      username: env.username, password: env.password,
    });
    await client.connect();
  });
  afterAll(async () => { await client?.close(); });

  it("returns a list including the configured share", async () => {
    const shares = await client.listShares();
    const names = shares.map((s) => s.name);
    expect(names).toContain(env.share);
  });
});
