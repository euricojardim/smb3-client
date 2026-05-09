// Create a temp file, stat it to inspect metadata, then clean up.
import { loadEnv, connectClient } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);
const path = `${env.share}/__node_smb3_example_stat/probe.txt`;
const dir = `${env.share}/__node_smb3_example_stat`;

try {
  console.log(`setting up working directory ${dir} ...`);
  try { await client.rmdir(dir); } catch { /* may not exist */ }
  await client.mkdir(dir);

  const content = Buffer.from("stat probe content", "utf8");
  console.log(`writing ${path} ...`);
  await client.writeFile(path, content);

  console.log("stat result:");
  const s = await client.stat(path);
  console.log(`  size:        ${s.size} bytes`);
  console.log(`  isFile:      ${s.isFile}`);
  console.log(`  isDirectory: ${s.isDirectory}`);
  console.log(`  readonly:    ${s.readonly}`);
  console.log(`  hidden:      ${s.hidden}`);
  console.log(`  archive:     ${s.archive}`);
  console.log(`  ctime:       ${s.ctime.toISOString()}`);
  console.log(`  mtime:       ${s.mtime.toISOString()}`);
  console.log(`  atime:       ${s.atime.toISOString()}`);

  if (s.size !== content.length) {
    throw new Error(`stat size mismatch: expected ${content.length}, got ${s.size}`);
  }
  if (!s.isFile) {
    throw new Error("stat did not report isFile=true");
  }

  console.log("assertions passed");

  console.log("cleaning up ...");
  await client.rm(path);
  await client.rmdir(dir);
} finally {
  await client.close();
}

console.log("done");
