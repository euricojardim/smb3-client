// Create a temp dir with three files, list names and Dirent objects, clean up.
import { loadEnv, connectClient } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const dir = `${env.share}/__node_smb3_example_listdir`;

try {
  console.log(`setting up ${dir} ...`);
  try {
    const existing = await client.readdir(dir) as string[];
    for (const name of existing) {
      try { await client.rm(`${dir}/${name}`); } catch { /* ignore */ }
    }
    await client.rmdir(dir);
  } catch { /* may not exist */ }
  await client.mkdir(dir);

  const files = ["a.txt", "b.txt", "c.txt"];
  for (const f of files) {
    console.log(`writing ${dir}/${f} ...`);
    await client.writeFile(`${dir}/${f}`, Buffer.from(f));
  }

  // Plain name listing.
  const names = await client.readdir(dir) as string[];
  console.log("readdir (names):", names.sort());

  for (const expected of files) {
    if (!names.includes(expected)) {
      throw new Error(`missing "${expected}" in readdir result`);
    }
  }

  // Dirent listing.
  const dirents = await client.readdir(dir, { withFileTypes: true });
  console.log("readdir (withFileTypes):");
  for (const d of dirents) {
    console.log(`  ${d.name}  isFile=${d.isFile()}  isDirectory=${d.isDirectory()}`);
  }

  console.log("cleaning up ...");
  for (const f of files) {
    await client.rm(`${dir}/${f}`);
  }
  await client.rmdir(dir);
} finally {
  await client.close();
}

console.log("done");
