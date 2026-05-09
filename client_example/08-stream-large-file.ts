// Stream a 4 MiB random buffer up via pipeline, stream it back, SHA-256 verify.
import { loadEnv, connectClient } from "./_common.js";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { randomBytes, createHash } from "node:crypto";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_streams`;
const path = `${dir}/big.bin`;

try {
  console.log(`setting up ${dir} ...`);
  try { await client.rmdir(dir); } catch { /* may not exist */ }
  await client.mkdir(dir);

  const SIZE = 4 * 1024 * 1024;
  const data = randomBytes(SIZE);
  const expectedHash = createHash("sha256").update(data).digest("hex");
  console.log(`generated ${SIZE / 1024} KiB, SHA-256: ${expectedHash.slice(0, 16)}...`);

  // Upload via stream.
  const uploadStart = Date.now();
  await pipeline(Readable.from(data), client.createWriteStream(path));
  const uploadMs = Date.now() - uploadStart;
  console.log(`upload: ${uploadMs} ms  (${((SIZE / uploadMs) * 1000 / 1024 / 1024).toFixed(1)} MiB/s)`);

  // Download via stream.
  const downloadStart = Date.now();
  const chunks: Buffer[] = [];
  for await (const chunk of client.createReadStream(path)) {
    chunks.push(chunk as Buffer);
  }
  const downloadMs = Date.now() - downloadStart;
  const got = Buffer.concat(chunks);
  console.log(`download: ${downloadMs} ms  (${((got.length / downloadMs) * 1000 / 1024 / 1024).toFixed(1)} MiB/s)`);

  if (got.length !== data.length) {
    throw new Error(`length mismatch: expected ${data.length}, got ${got.length}`);
  }
  const gotHash = createHash("sha256").update(got).digest("hex");
  if (gotHash !== expectedHash) {
    throw new Error(`SHA-256 mismatch:\n  expected: ${expectedHash}\n  got:      ${gotHash}`);
  }
  console.log("SHA-256 verified");

  console.log("cleaning up ...");
  await client.rm(path);
  await client.rmdir(dir);
} finally {
  await client.close();
}

console.log("done");
