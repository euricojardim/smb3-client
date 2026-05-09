const MAX_PAYLOAD = 0x00ffffff;

export function frame(payload: Buffer): Buffer {
  if (payload.length > MAX_PAYLOAD) {
    throw new RangeError(`frame: payload ${payload.length} exceeds 24-bit limit`);
  }
  const hdr = Buffer.alloc(4);
  // 1 byte zero + 24-bit BE length
  hdr[0] = 0;
  hdr[1] = (payload.length >>> 16) & 0xff;
  hdr[2] = (payload.length >>> 8) & 0xff;
  hdr[3] = payload.length & 0xff;
  return Buffer.concat([hdr, payload]);
}

export class FrameReader {
  private buf: Buffer = Buffer.alloc(0);

  feed(chunk: Buffer): void {
    this.buf = this.buf.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.buf, chunk]);
  }

  next(): Buffer | null {
    if (this.buf.length < 4) return null;
    const len = (this.buf[1]! << 16) | (this.buf[2]! << 8) | this.buf[3]!;
    if (this.buf.length < 4 + len) return null;
    const payload = Buffer.from(this.buf.subarray(4, 4 + len));
    this.buf = Buffer.from(this.buf.subarray(4 + len));
    return payload;
  }
}
