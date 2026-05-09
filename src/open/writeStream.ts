import { Writable } from "node:stream";
import type { Open } from "./open.js";
import { writeAll } from "./write.js";

export interface WriteStreamOptions {
  start?: bigint;
  highWaterMark?: number;
  /** When true (default), CLOSE the underlying handle on stream end. */
  closeOnFinal?: boolean;
}

export function createWriteStream(open: Open, opts: WriteStreamOptions = {}): Writable {
  const max = open.tree.conn.state?.maxWriteSize ?? 65536;
  const hwm = opts.highWaterMark ?? max;
  let offset = opts.start ?? 0n;
  const closeOnFinal = opts.closeOnFinal ?? true;

  return new Writable({
    highWaterMark: hwm,
    write(chunk, _enc, cb) {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      writeAll(open, offset, buf).then(
        () => {
          offset += BigInt(buf.length);
          cb();
        },
        (err) => cb(err as Error),
      );
    },
    final(cb) {
      if (!closeOnFinal) return cb();
      open.close().then(() => cb(), (err) => cb(err as Error));
    },
    destroy(err, cb) {
      if (!closeOnFinal) return cb(err);
      open.close().then(() => cb(err), () => cb(err));
    },
  });
}
