import { it, expect } from "vitest";
import { integrationDescribe, readIntegrationEnv } from "../helpers/integrationGate.js";
import { TcpTransport } from "../../src/transport/socket.js";
import { Connection } from "../../src/connection/connection.js";
import { Dialect } from "../../src/wire/commands.js";

integrationDescribe("integration: negotiate", () => {
  it("connects to the SMB server and negotiates a 2.1+ dialect", async () => {
    const env = readIntegrationEnv()!;
    const t = await TcpTransport.connect(env.host, env.port, { timeoutMs: 10_000 });
    const conn = new Connection(t);
    try {
      const r = await conn.open();
      expect(r.dialect).toBeGreaterThanOrEqual(Dialect.SMB_2_1_0);
      expect(r.serverGuid.length).toBe(16);
      expect(r.maxReadSize).toBeGreaterThan(0);
    } finally {
      conn.close();
    }
  });
});
