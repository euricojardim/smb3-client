// Create a directory, confirm it appears in the parent listing, then remove it.
import { loadEnv, connectClient, ensureCleanDir, removeDirRecursively } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const base = `${env.share}/__node_smb3_example_mkrmdir`;
const sub = `${base}/newdir`;

try {
  // Ensure the base working directory exists.
  console.log(`setting up ${base} ...`);
  await ensureCleanDir(client, base);

  console.log(`creating ${sub} ...`);
  await client.mkdir(sub);

  let names = await client.readdir(base) as string[];
  console.log("after mkdir:", names);
  if (!names.includes("newdir")) throw new Error("newdir not found after mkdir");

  const s = await client.stat(sub);
  if (!s.isDirectory) throw new Error(`stat shows isDirectory=false for ${sub}`);
  console.log(`stat confirms isDirectory=true`);

  console.log(`removing ${sub} ...`);
  await client.rmdir(sub);

  names = await client.readdir(base) as string[];
  console.log("after rmdir:", names);
  if (names.includes("newdir")) throw new Error("newdir still present after rmdir");

  console.log("assertions passed");

  console.log("cleaning up base dir ...");
  await removeDirRecursively(client, base);
} finally {
  await client.close();
}

console.log("done");
