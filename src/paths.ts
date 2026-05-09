import { SmbError } from "./errors.js";
import { NTStatus } from "./wire/commands.js";

export function splitSharePath(p: string): { share: string; rest: string } {
  if (!p || p.length === 0) {
    throw new SmbError({ status: NTStatus.STATUS_INVALID_PARAMETER, message: "empty path" });
  }
  if (p.startsWith("\\\\") || /^[A-Za-z]:/.test(p)) {
    throw new SmbError({ status: NTStatus.STATUS_INVALID_PARAMETER, message: `bad path: ${p}` });
  }
  const parts = p.split("/").filter((x) => x.length > 0);
  if (parts.some((x) => x === "..")) {
    throw new SmbError({ status: NTStatus.STATUS_INVALID_PARAMETER, message: "path contains .." });
  }
  if (parts.length === 0) {
    throw new SmbError({ status: NTStatus.STATUS_INVALID_PARAMETER, message: "empty share" });
  }
  return { share: parts[0]!, rest: parts.slice(1).join("/") };
}

export function toSmbPath(rest: string): string {
  return rest.replace(/^[\\/]+/, "").replace(/\//g, "\\");
}

export function smbTimeToDate(filetime: bigint): Date {
  if (filetime === 0n) return new Date(0);
  const epochDiffSec = 11644473600n;
  const ms = Number((filetime / 10000n) - (epochDiffSec * 1000n));
  return new Date(ms);
}
