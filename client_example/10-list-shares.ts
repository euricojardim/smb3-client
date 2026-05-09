// Enumerate all shares on the server via DCE/RPC srvsvc.NetrShareEnum.
import { loadEnv, connectClient } from "./_common.js";

const env = loadEnv();
const client = await connectClient(env);

try {
  console.log(`listing shares on ${env.host} ...`);
  const shares = await client.listShares();

  console.log(`found ${shares.length} share(s):`);
  for (const s of shares) {
    console.log(`  ${s.name.padEnd(20)} type=${s.type.padEnd(8)} comment="${s.comment}"`);
  }

  const names = shares.map((s) => s.name);
  if (!names.includes(env.share)) {
    throw new Error(
      `expected SMB_TEST_SHARE="${env.share}" in share list, got: [${names.join(", ")}]`,
    );
  }
  console.log(`confirmed SMB_TEST_SHARE="${env.share}" is present`);
} finally {
  await client.close();
}

console.log("done");
