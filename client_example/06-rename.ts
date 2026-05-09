// Create a file, rename it, verify old name is gone and new name appears.
import { loadEnv, connectClient } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_rename`;
const before = `${dir}/original.txt`;
const after = `${dir}/renamed.txt`;

try {
  console.log(`setting up ${dir} ...`);
  try { await client.rmdir(dir); } catch { /* may not exist */ }
  await client.mkdir(dir);

  console.log(`writing ${before} ...`);
  await client.writeFile(before, Buffer.from("rename test"));

  let names = await client.readdir(dir) as string[];
  console.log("before rename:", names);
  if (!names.includes("original.txt")) throw new Error("original.txt not found before rename");

  console.log(`renaming to ${after} ...`);
  await client.rename(before, after);

  names = await client.readdir(dir) as string[];
  console.log("after rename:", names);

  if (names.includes("original.txt")) throw new Error("original.txt still present after rename");
  if (!names.includes("renamed.txt")) throw new Error("renamed.txt not found after rename");

  console.log("assertions passed");

  console.log("cleaning up ...");
  await client.rm(after);
  await client.rmdir(dir);
} finally {
  await client.close();
}

console.log("done");
