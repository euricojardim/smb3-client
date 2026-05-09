import { EventEmitter } from "node:events";
import { FrameReader } from "../../src/transport/framer.js";
import type { Transport } from "../../src/transport/socket.js";

export class FakeTransport extends EventEmitter implements Transport {
  private sendCb: ((frame: Buffer) => void) | null = null;
  private reader = new FrameReader();
  private closed = false;

  onSend(cb: (frame: Buffer) => void): void {
    this.sendCb = cb;
  }

  /** Server-to-client: deliver a raw SMB2 message (no NBSS header — added here). */
  deliver(smb2: Buffer): void {
    if (this.closed) return;
    setImmediate(() => this.emit("message", smb2));
  }

  send(frame: Buffer): void {
    if (this.closed) throw new Error("FakeTransport: closed");
    this.reader.feed(frame);
    // Just hand the full frame (with its NBSS header) to the test callback.
    this.sendCb?.(frame);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.emit("close");
  }
}
