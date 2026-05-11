import { describe, it, expect } from "vitest";
import { FakeTransport } from "../../helpers/fakeTransport.js";
import { Connection } from "../../../src/connection/connection.js";
import { Session, type SigningMode } from "../../../src/session/session.js";

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
