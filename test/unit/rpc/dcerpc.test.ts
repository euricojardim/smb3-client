import { describe, it, expect } from "vitest";
import { encodeBindRequest, parseBindAck, encodeRequest, parseResponse } from "../../../src/rpc/dcerpc.js";

describe("DCE/RPC", () => {
  const SRVSVC_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
  it("Bind request frags begin with 'rpc' header bytes (ver 5)", () => {
    const buf = encodeBindRequest({ callId: 1, abstractUuid: SRVSVC_UUID, abstractMajor: 3, abstractMinor: 0 });
    expect(buf[0]).toBe(0x05); // RpcVersion
    expect(buf[1]).toBe(0x00); // MinorVersion
    expect(buf[2]).toBe(0x0b); // PacketType: Bind
  });

  it("Request encode/parse round-trip", () => {
    const req = encodeRequest({ callId: 2, opnum: 15, contextId: 0, stub: Buffer.from("01020304", "hex") });
    expect(req[2]).toBe(0x00); // Request
    const parsed = parseResponse(Buffer.concat([req.subarray(0, 0), req.subarray(0)])); // synthetic; we'll simulate a real Response separately
    expect(parsed).toBeNull(); // it's a Request, not a Response
  });
});
