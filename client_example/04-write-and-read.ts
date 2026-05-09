// Write a 64 KiB random buffer, read it back, verify via SHA-256.
import { loadEnv, connectClient, ensureCleanDir, removeDirRecursively } from "./_common.js";
import { randomBytes, createHash } from "node:crypto";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_writeread`;
const path = `${dir}/random64k.bin`;

try {
  console.log(`setting up ${dir} ...`);
  await ensureCleanDir(client, dir);

  const SIZE = 64 * 1024;
  const data = randomBytes(SIZE);
  const expectedHash = createHash("sha256").update(data).digest("hex");

  console.log(`writing ${SIZE} random bytes (SHA-256: ${expectedHash.slice(0, 16)}...) ...`);
  await client.writeFile(path, data);

  console.log("reading back ...");
  const got = await client.readFile(path);

  if (got.length !== data.length) {
    throw new Error(`length mismatch: expected ${data.length}, got ${got.length}`);
  }

  const gotHash = createHash("sha256").update(got).digest("hex");
  if (gotHash !== expectedHash) {
    throw new Error(`SHA-256 mismatch:\n  expected: ${expectedHash}\n  got:      ${gotHash}`);
  }

  console.log(`SHA-256 verified: ${gotHash}`);

  console.log("cleaning up ...");
  await removeDirRecursively(client, dir);
} finally {
  await client.close();
}

console.log("done");
