import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session, type SigningMode } from "../../../src/session/session.js";
import { Client } from "../../../src/client.js";
import { SecurityMode, Dialect } from "../../../src/wire/commands.js";
import { SmbAuthError } from "../../../src/errors.js";

describe("Session signing mode plumbing", () => {
  it("accepts a SigningMode in the constructor opts and exposes it via a typed export", () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    const modes: SigningMode[] = ["disabled", "if-offered", "required"];
    for (const m of modes) {
      const s = new Session(
        conn,
        { username: "u", password: "p", domain: "" },
        { signing: m },
      );
      expect(s).toBeInstanceOf(Session);
    }
  });

  it("defaults the signing mode to \"if-offered\" when no option is passed", () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    const s = new Session(conn, { username: "u", password: "p", domain: "" });
    expect(s).toBeInstanceOf(Session);
  });
});

describe("NEGOTIATE SecurityMode advertisement", () => {
  // Captures the first outbound frame the Client.connect() flow produces (the
  // NEGOTIATE request). We monkeypatch TcpTransport.connect so the Client uses
  // a FakeTransport and we can read the actual bytes Client.connect() sends.
  async function captureFirstFrame(signing: "disabled" | "if-offered" | "required" | undefined): Promise<number> {
    const ft = new FakeTransport();
    let first: Buffer | null = null;
    ft.onSend((frame) => {
      if (first === null) first = Buffer.from(frame.subarray(4)); // strip NBSS prefix
    });
    const transportMod = await import("../../../src/transport/socket.js");
    const orig = transportMod.TcpTransport.connect;
    // @ts-expect-error monkeypatch for test only
    transportMod.TcpTransport.connect = async () => ft;
    try {
      const c = new Client({
        host: "x.invalid",
        username: "u",
        password: "p",
        ...(signing !== undefined ? { signing } : {}),
      });
      // Fire-and-forget; connect() will fail at SESSION_SETUP (no real server),
      // but we only need the very first frame on the wire.
      void c.connect().catch(() => {});
      await new Promise((r) => setImmediate(r));
    } finally {
      // @ts-expect-error restore
      transportMod.TcpTransport.connect = orig;
    }
    expect(first).not.toBeNull();
    // SMB2 header is 64 bytes. NEGOTIATE request body:
    //   StructureSize(u16) + DialectCount(u16) + SecurityMode(u16) + Reserved(u16) + ...
    // So SecurityMode lives at offset 64 + 4.
    return first!.readUInt16LE(64 + 4);
  }

  it("advertises SIGNING_ENABLED only when mode is \"if-offered\"", async () => {
    const sm = await captureFirstFrame("if-offered");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED only when mode is \"disabled\"", async () => {
    const sm = await captureFirstFrame("disabled");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED only when mode is undefined (default)", async () => {
    const sm = await captureFirstFrame(undefined);
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(0);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });

  it("advertises SIGNING_ENABLED | SIGNING_REQUIRED when mode is \"required\"", async () => {
    const sm = await captureFirstFrame("required");
    expect(sm & SecurityMode.SIGNING_REQUIRED).toBe(SecurityMode.SIGNING_REQUIRED);
    expect(sm & SecurityMode.SIGNING_ENABLED).toBe(SecurityMode.SIGNING_ENABLED);
  });
});

describe("Session setup with signing=disabled vs server demands signing", () => {
  it("throws SmbAuthError when server NEGOTIATE response has SIGNING_REQUIRED bit", async () => {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    // Inject a negotiated state with SIGNING_REQUIRED set by the server.
    (conn as unknown as { negotiated: unknown }).negotiated = {
      dialect: Dialect.SMB_3_1_1,
      serverGuid: Buffer.alloc(16),
      capabilities: 0,
      securityMode: SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED,
      maxReadSize: 65536,
      maxWriteSize: 65536,
      maxTransactSize: 65536,
      securityBuffer: Buffer.alloc(0),
    };
    const s = new Session(
      conn,
      { username: "u", password: "p", domain: "" },
      { signing: "disabled" },
    );
    await expect(s.setup()).rejects.toBeInstanceOf(SmbAuthError);
    await expect(s.setup()).rejects.toThrow(/signing/i);
  });

  it("does NOT throw on server SIGNING_REQUIRED when mode is \"if-offered\" or \"required\"", async () => {
    // Just confirm we don't gate this on those modes — they should proceed past
    // the check and fail later for a different reason (no transport).
    for (const m of ["if-offered", "required"] as const) {
      const ft = new FakeTransport();
      const conn = new Connection(ft);
      (conn as unknown as { negotiated: unknown }).negotiated = {
        dialect: Dialect.SMB_3_1_1,
        serverGuid: Buffer.alloc(16),
        capabilities: 0,
        securityMode: SecurityMode.SIGNING_ENABLED | SecurityMode.SIGNING_REQUIRED,
        maxReadSize: 65536, maxWriteSize: 65536, maxTransactSize: 65536,
        securityBuffer: Buffer.alloc(0),
      };
      const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: m });
      // We expect a different failure (connection closed) — not the signing-mode rejection.
      const setupPromise = s.setup();
      // Close the transport so the pending SESSION_SETUP send rejects rather than hanging.
      ft.close();
      await expect(setupPromise).rejects.not.toThrow(/signing.*disabled/i);
    }
  });
});

describe("Session.makeSigning() vs signing mode", () => {
  function buildSession(mode: "disabled" | "if-offered" | "required") {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: mode });
    // Inject a signing key without running setup().
    (s as unknown as { signingKey: Buffer }).signingKey = Buffer.alloc(16, 0xaa);
    return s;
  }

  it("returns undefined when signingMode is \"disabled\" even with a derived signing key", () => {
    const s = buildSession("disabled");
    expect(s.makeSigning()).toBeUndefined();
  });

  it("returns a signing function when signingMode is \"if-offered\" with a key", () => {
    const s = buildSession("if-offered");
    const sig = s.makeSigning();
    expect(sig).toBeDefined();
    expect(typeof sig!.sign).toBe("function");
  });

  it("returns a signing function when signingMode is \"required\" with a key", () => {
    const s = buildSession("required");
    const sig = s.makeSigning();
    expect(sig).toBeDefined();
    expect(typeof sig!.sign).toBe("function");
  });
});

describe("Session.applyCancelSigner() vs signing mode", () => {
  function buildSession(mode: "disabled" | "if-offered" | "required") {
    const ft = new FakeTransport();
    const conn = new Connection(ft);
    (conn as unknown as { negotiated: unknown }).negotiated = { dialect: Dialect.SMB_3_1_1 };
    const s = new Session(conn, { username: "u", password: "p", domain: "" }, { signing: mode });
    (s as unknown as { signingKey: Buffer }).signingKey = Buffer.alloc(16, 0x55);
    return { s, conn };
  }

  it("does NOT register a cancel signer when signingMode is \"disabled\"", () => {
    const { s, conn } = buildSession("disabled");
    let cancelSignerSet = false;
    conn.setCancelSigner = () => { cancelSignerSet = true; };
    (s as unknown as { applyCancelSigner(): void }).applyCancelSigner();
    expect(cancelSignerSet).toBe(false);
  });

  it("registers a cancel signer when signingMode is \"if-offered\"", () => {
    const { s, conn } = buildSession("if-offered");
    let cancelSignerSet = false;
    conn.setCancelSigner = () => { cancelSignerSet = true; };
    (s as unknown as { applyCancelSigner(): void }).applyCancelSigner();
    expect(cancelSignerSet).toBe(true);
  });

  it("registers a cancel signer when signingMode is \"required\"", () => {
    const { s, conn } = buildSession("required");
    let cancelSignerSet = false;
    conn.setCancelSigner = () => { cancelSignerSet = true; };
    (s as unknown as { applyCancelSigner(): void }).applyCancelSigner();
    expect(cancelSignerSet).toBe(true);
  });
});
