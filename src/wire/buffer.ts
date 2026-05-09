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
