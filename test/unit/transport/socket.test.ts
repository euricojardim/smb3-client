import { describe, it, expect } from "vitest";
import { createServer } from "node:net";
import { TcpTransport } from "../../../src/transport/socket.js";
import { frame } from "../../../src/transport/framer.js";

describe("TcpTransport", () => {
  it("connects, sends, and emits framed messages", async () => {
    const received = new Promise<Buffer>((resolve) => {
      const server = createServer((sock) => {
        sock.once("data", (_chunk) => {
          // Echo a synthetic SMB-shaped payload back, framed.
          sock.write(frame(Buffer.from("hello", "ascii")));
          sock.end();
          server.close();
        });
      }).listen(0, "127.0.0.1");
      server.on("listening", async () => {
        const addr = server.address();
        if (typeof addr === "string" || !addr) throw new Error("bad addr");
        const t = await TcpTransport.connect("127.0.0.1", addr.port);
        const msgs: Buffer[] = [];
        t.on("message", (m) => msgs.push(m));
        t.on("close", () => resolve(msgs[0]!));
        t.send(frame(Buffer.from("ping", "ascii")));
      });
    });
    const msg = await received;
    expect(msg.toString("ascii")).toBe("hello");
  });
});
