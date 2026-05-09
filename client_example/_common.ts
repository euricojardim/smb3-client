// Shared helpers: env loading and Client construction for all examples.
import { Client } from "../src/index.js";
import type { ClientOptions } from "../src/index.js";

export interface Env {
  host: string;
  port: number;
  domain: string;
  username: string;
  password: string;
  share: string;
}

export function loadEnv(): Env {
  const required: Record<string, string | undefined> = {
    SMB_TEST_HOST: process.env["SMB_TEST_HOST"],
    SMB_TEST_USERNAME: process.env["SMB_TEST_USERNAME"],
    SMB_TEST_PASSWORD: process.env["SMB_TEST_PASSWORD"],
    SMB_TEST_SHARE: process.env["SMB_TEST_SHARE"],
  };

  const missing = Object.entries(required)
    .filter(([, v]) => !v)
    .map(([k]) => k);

  if (missing.length > 0) {
    console.error("Missing required environment variables:");
    for (const k of missing) console.error(`  ${k}`);
    console.error("\nSet them directly or load from .env:");
    console.error("  set -a && . ./.env && set +a");
    process.exit(1);
  }

  return {
    host: required["SMB_TEST_HOST"]!,
    port: Number(process.env["SMB_TEST_PORT"] ?? 445),
    domain: process.env["SMB_TEST_DOMAIN"] ?? "",
    username: required["SMB_TEST_USERNAME"]!,
    password: required["SMB_TEST_PASSWORD"]!,
    share: required["SMB_TEST_SHARE"]!,
  };
}

export async function connectClient(env: Env, opts?: Partial<ClientOptions>): Promise<Client> {
  const client = new Client({
    host: env.host,
    port: env.port,
    domain: env.domain,
    username: env.username,
    password: env.password,
    ...opts,
  });
  await client.connect();
  return client;
}

/**
 * Best-effort recursive removal of a directory and everything inside it.
 * Silently swallows "not found" errors so it's safe to call before mkdir
 * and again on cleanup. Useful because Client.rmdir is non-recursive and
 * fails with ENOTEMPTY if leftover files (or files dropped in by another
 * client like Windows Explorer) are still in the dir.
 */
export async function removeDirRecursively(client: Client, dir: string): Promise<void> {
  let entries: string[];
  try {
    entries = (await client.readdir(dir)) as string[];
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code === "ENOENT") return;
    throw err;
  }

  for (const name of entries) {
    const child = `${dir}/${name}`;
    try {
      await client.rm(child);
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code === "EISDIR" || code === "EACCES") {
        await removeDirRecursively(client, child);
      } else if (code !== "ENOENT") {
        throw err;
      }
    }
  }

  try {
    await client.rmdir(dir);
  } catch (err) {
    const code = (err as { code?: string }).code;
    if (code !== "ENOENT") throw err;
  }
}

/**
 * Clears the directory if present, then creates it fresh.
 */
export async function ensureCleanDir(client: Client, dir: string): Promise<void> {
  await removeDirRecursively(client, dir);
  await client.mkdir(dir);
}
