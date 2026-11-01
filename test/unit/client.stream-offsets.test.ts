import { describe, it, expect, vi } from "vitest";
import { Client } from "../../src/client.js";
import { Open } from "../../src/open/open.js";
import { CreateDisposition } from "../../src/wire/structs/create.js";

describe("Client stream offsets", () => {
  it("rejects a negative or fractional start", () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    expect(() => c.createReadStream("share/f", { start: -1 })).toThrow(RangeError);
    expect(() => c.createWriteStream("share/f", { start: 1.5 })).toThrow(RangeError);
  });

  it("keeps the file when writing from an offset, truncates it from 0", async () => {
    const c = new Client({ host: "x", username: "u", password: "p" });
    (c as unknown as { treeFor: () => Promise<unknown> }).treeFor = async () => ({});
    const seen: number[] = [];
    const spy = vi.spyOn(Open, "create").mockImplementation(async (_tree, req) => {
      seen.push(req.createDisposition);
      throw new Error("stop here");
    });
    for (const start of [0, 10]) {
      await new Promise<void>((resolve) => {
        c.createWriteStream("share/f", { start }).on("error", () => resolve());
      });
    }
    spy.mockRestore();
    expect(seen).toEqual([CreateDisposition.OVERWRITE_IF, CreateDisposition.OPEN_IF]);
  });
});
