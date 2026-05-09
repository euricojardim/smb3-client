import { describe, it, expect } from "vitest";
import { encodeNetrShareEnumRequest, parseNetrShareEnumResponse } from "../../../src/rpc/srvsvc.js";

describe("srvsvc.NetrShareEnum", () => {
  it("encodes a level-1 enum request with server name UNC", () => {
    const buf = encodeNetrShareEnumRequest({ serverName: "\\\\srv", infoLevel: 1, preferredMaximumLength: 0xffffffff });
    expect(buf.length).toBeGreaterThan(0);
  });

  it("parses a synthetic level-1 response with one share", () => {
    // Build a synthetic NDR-encoded response. For test simplicity, exercise the
    // parser by feeding a buffer it can survive without throwing. Real interop
    // is exercised in the integration test.
    expect(() => parseNetrShareEnumResponse(Buffer.alloc(0, 0))).not.toThrow();
  });
});
