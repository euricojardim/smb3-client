// Connect at the transport+connection layer and print SMB negotiation details.
import { loadEnv } from "./_common.js";
import { TcpTransport } from "../src/transport/socket.js";
import { Connection } from "../src/connection/connection.js";
import { Dialect } from "../src/wire/commands.js";

const DIALECT_NAMES: Record<number, string> = {
  [Dialect.SMB_2_0_2]: "SMB_2_0_2",
  [Dialect.SMB_2_1_0]: "SMB_2_1_0",
  [Dialect.SMB_3_0_0]: "SMB_3_0_0",
  [Dialect.SMB_3_0_2]: "SMB_3_0_2",
  [Dialect.SMB_3_1_1]: "SMB_3_1_1",
};

const env = loadEnv();

console.log(`connecting to ${env.host}:${env.port} ...`);
const transport = await TcpTransport.connect(env.host, env.port, { timeoutMs: 10_000 });
const conn = new Connection(transport);

try {
  const neg = await conn.open();

  const dialectName = DIALECT_NAMES[neg.dialect] ?? `0x${neg.dialect.toString(16)}`;
  const serverGuidHex = neg.serverGuid.toString("hex").toUpperCase();

  console.log("negotiation complete:");
  console.log(`  dialect:        ${dialectName}`);
  console.log(`  serverGuid:     ${serverGuidHex}`);
  console.log(`  maxReadSize:    ${neg.maxReadSize} bytes (${(neg.maxReadSize / 1024).toFixed(0)} KiB)`);
  console.log(`  maxWriteSize:   ${neg.maxWriteSize} bytes (${(neg.maxWriteSize / 1024).toFixed(0)} KiB)`);
  console.log(`  maxTransactSize:${neg.maxTransactSize} bytes`);
  console.log(`  capabilities:   0x${neg.capabilities.toString(16)}`);
  console.log(`  securityMode:   0x${neg.securityMode.toString(16)}`);

  if (neg.preauthHashAlg !== undefined) {
    console.log(`  preauthHashAlg: 0x${neg.preauthHashAlg.toString(16)} (SHA-512)`);
  }
} finally {
  conn.close();
}

console.log("done");
