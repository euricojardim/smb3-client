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
