import { describe } from "vitest";

export interface IntegrationEnv {
  host: string;
  port: number;
  domain: string;
  username: string;
  password: string;
  share: string;
}

export function readIntegrationEnv(): IntegrationEnv | null {
  const host = process.env.SMB_TEST_HOST;
  const username = process.env.SMB_TEST_USERNAME;
  const password = process.env.SMB_TEST_PASSWORD;
  const share = process.env.SMB_TEST_SHARE;
  if (!host || !username || !password || !share) return null;
  return {
    host,
    port: Number(process.env.SMB_TEST_PORT ?? 445),
    domain: process.env.SMB_TEST_DOMAIN ?? "",
    username,
    password,
    share,
  };
}

export const integrationDescribe: typeof describe = ((name, fn) => {
  const env = readIntegrationEnv();
  if (!env) return describe.skip(name, fn);
  return describe(name, fn);
}) as typeof describe;
