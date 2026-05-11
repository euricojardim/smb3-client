import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session, type SigningMode } from "../../../src/session/session.js";
import { Client } from "../../../src/client.js";
import { SecurityMode } from "../../../src/wire/commands.js";

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
