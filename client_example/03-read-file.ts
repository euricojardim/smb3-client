// Write a known string to a temp file, read it back, assert byte equality.
import { loadEnv, connectClient, ensureCleanDir, removeDirRecursively } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_readfile`;
const path = `${dir}/big.iso`;

try {
  console.log(`setting up ${dir} ...`);
  await ensureCleanDir(client, dir);

  const original = Buffer.from("hello from node-smb3", "utf8");
  console.log(`writing ${original.length} bytes to ${path} ...`);
  await client.writeFile(path, original);

  console.log("reading file back ...");
  const got = await client.readFile(path);

  if (!got.equals(original)) {
    throw new Error(
      `content mismatch: expected "${original.toString("utf8")}", got "${got.toString("utf8")}"`,
    );
  }

  console.log(`read ${got.length} bytes — content matches`);

  // Also exercise the encoding overload.
  const text = await client.readFile(path, "utf8");
  if (text !== original.toString("utf8")) {
    throw new Error(`encoding overload mismatch: got "${text}"`);
  }
  console.log(`encoding overload OK: "${text}"`);

  console.log("cleaning up ...");
  await removeDirRecursively(client, dir);
} finally {
  await client.close();
}

console.log("done");
