import { describe, it, expect } from "vitest";
import { splitSharePath, toSmbPath } from "../../src/paths.js";

describe("paths", () => {
  it("splits a share/path string", () => {
    expect(splitSharePath("public/dir/file.txt")).toEqual({ share: "public", rest: "dir/file.txt" });
    expect(splitSharePath("public")).toEqual({ share: "public", rest: "" });
  });

  it("rejects .. and absolute-style paths", () => {
    expect(() => splitSharePath("public/../etc")).toThrow();
    expect(() => splitSharePath("\\\\srv\\share")).toThrow();
    expect(() => splitSharePath("C:/x")).toThrow();
    expect(() => splitSharePath("")).toThrow();
  });

  it("toSmbPath converts forward slashes to backslashes and strips leading", () => {
    expect(toSmbPath("dir/sub/file.txt")).toBe("dir\\sub\\file.txt");
    expect(toSmbPath("")).toBe("");
    expect(toSmbPath("/leading")).toBe("leading");
  });
});
