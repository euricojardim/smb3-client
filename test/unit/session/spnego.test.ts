import { describe, it, expect } from "vitest";
import { wrapInitNegToken, wrapNegTokenResp, extractNtlmFromResp } from "../../../src/session/spnego.js";

describe("SPNEGO", () => {
  it("wraps an NTLMSSP NEGOTIATE blob in a NegTokenInit", () => {
    const ntlm = Buffer.from("4e544c4d535350", "hex"); // "NTLMSSP" prefix only — synthetic
    const wrapped = wrapInitNegToken(ntlm);
    // Outer must be application 0 (0x60)
    expect(wrapped[0]).toBe(0x60);
    // Must contain the NTLMSSP OID 1.3.6.1.4.1.311.2.2.10 encoded as 2b 06 01 04 01 82 37 02 02 0a
    expect(wrapped.indexOf(Buffer.from("2b06010401823702020a", "hex"))).toBeGreaterThan(0);
    // Must contain the NTLM token bytes verbatim
    expect(wrapped.indexOf(ntlm)).toBeGreaterThan(0);
  });

  it("wraps a continuation in a NegTokenResp and round-trips extractNtlmFromResp", () => {
    const ntlm = Buffer.from("4e544c4d5353500003000000", "hex"); // type 3 prefix
    const wrapped = wrapNegTokenResp(ntlm);
    const unwrapped = extractNtlmFromResp(wrapped);
    expect(unwrapped).toEqual(ntlm);
  });
});
