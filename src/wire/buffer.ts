export class Reader {
  offset = 0;
  constructor(private readonly buf: Buffer) {}

  remaining(): number {
    return this.buf.length - this.offset;
  }

  private need(n: number): void {
    if (this.remaining() < n) {
      throw new RangeError(`Reader: need ${n} bytes, have ${this.remaining()}`);
    }
  }

  u8(): number {
    this.need(1);
    const v = this.buf.readUInt8(this.offset);
    this.offset += 1;
    return v;
  }

  u16(): number {
    this.need(2);
    const v = this.buf.readUInt16LE(this.offset);
    this.offset += 2;
    return v;
  }

  u32(): number {
    this.need(4);
    const v = this.buf.readUInt32LE(this.offset);
    this.offset += 4;
    return v;
  }

  u64(): bigint {
    this.need(8);
    const v = this.buf.readBigUInt64LE(this.offset);
    this.offset += 8;
    return v;
  }

  bytes(n: number): Buffer {
    this.need(n);
    const v = Buffer.from(this.buf.subarray(this.offset, this.offset + n));
    this.offset += n;
    return v;
  }

  utf16(byteLength: number): string {
    this.need(byteLength);
    const v = this.buf.subarray(this.offset, this.offset + byteLength).toString("utf16le");
    this.offset += byteLength;
    return v;
  }

  sub(offset: number, length: number): Reader {
    if (offset < 0 || length < 0 || offset + length > this.buf.length) {
      throw new RangeError("Reader.sub: out of range");
    }
    return new Reader(Buffer.from(this.buf.subarray(offset, offset + length)));
  }

  view(): Buffer {
    return this.buf;
  }
}

export class Writer {
  private chunks: Buffer[] = [];
  private len = 0;

  get offset(): number {
    return this.len;
  }

  private push(b: Buffer): void {
    this.chunks.push(b);
    this.len += b.length;
  }

  u8(v: number): void {
    const b = Buffer.alloc(1);
    b.writeUInt8(v & 0xff, 0);
    this.push(b);
  }

  u16(v: number): void {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(v & 0xffff, 0);
    this.push(b);
  }

  u32(v: number): void {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(v >>> 0, 0);
    this.push(b);
  }

  u64(v: bigint): void {
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(v, 0);
    this.push(b);
  }

  bytes(b: Buffer): void {
    this.push(Buffer.from(b));
  }

  utf16(s: string): void {
    this.push(Buffer.from(s, "utf16le"));
  }

  pad(n: number): void {
    if (n > 0) this.push(Buffer.alloc(n));
  }

  padTo(boundary: number): void {
    const rem = this.len % boundary;
    if (rem !== 0) this.pad(boundary - rem);
  }

  buffer(): Buffer {
    return Buffer.concat(this.chunks, this.len);
  }
}
