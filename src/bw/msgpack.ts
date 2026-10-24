// A MessagePack decoder, just enough for the SignalR messages of the
// Bitwarden notifications hub. Input comes from the network: every read is
// bounds-checked and nesting is limited, so malformed data throws instead of
// hanging or exhausting memory.

export type MsgValue = null | boolean | number | bigint | string | Uint8Array | Date | MsgValue[] | MsgMap | MsgExt;
export interface MsgMap {
  [key: string]: MsgValue;
}
export interface MsgExt {
  ext: number;
  data: Uint8Array;
}

export class MsgPackError extends Error {
  override name = "MsgPackError";
}

const MAX_DEPTH = 32;
const decoder = new TextDecoder("utf-8", { fatal: true });

class Reader {
  pos = 0;
  private readonly view: DataView;
  constructor(private readonly bytes: Uint8Array) {
    this.view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  }
  private need(n: number) {
    if (this.pos + n > this.bytes.length) throw new MsgPackError("Truncated MessagePack data");
  }
  u8() {
    this.need(1);
    return this.bytes[this.pos++]!;
  }
  u16() {
    this.need(2);
    const v = this.view.getUint16(this.pos);
    this.pos += 2;
    return v;
  }
  u32() {
    this.need(4);
    const v = this.view.getUint32(this.pos);
    this.pos += 4;
    return v;
  }
  take(n: number) {
    this.need(n);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  number(kind: "i8" | "i16" | "i32" | "f32" | "f64", size: number): number {
    this.need(size);
    const at = this.pos;
    this.pos += size;
    switch (kind) {
      case "i8":
        return this.view.getInt8(at);
      case "i16":
        return this.view.getInt16(at);
      case "i32":
        return this.view.getInt32(at);
      case "f32":
        return this.view.getFloat32(at);
      case "f64":
        return this.view.getFloat64(at);
    }
  }
  big(signed: boolean): number | bigint {
    this.need(8);
    const v = signed ? this.view.getBigInt64(this.pos) : this.view.getBigUint64(this.pos);
    this.pos += 8;
    return v >= BigInt(Number.MIN_SAFE_INTEGER) && v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
}

/** Decodes one MessagePack value that must fill `bytes` exactly. */
export function decodeMsgPack(bytes: Uint8Array): MsgValue {
  const r = new Reader(bytes);
  const value = read(r, 0);
  if (r.pos !== bytes.length) throw new MsgPackError("Trailing bytes after MessagePack value");
  return value;
}

function read(r: Reader, depth: number): MsgValue {
  if (depth > MAX_DEPTH) throw new MsgPackError("MessagePack data is nested too deeply");
  const b = r.u8();
  if (b <= 0x7f) return b;
  if (b >= 0xe0) return b - 0x100;
  if ((b & 0xf0) === 0x80) return readMap(r, b & 0x0f, depth);
  if ((b & 0xf0) === 0x90) return readArray(r, b & 0x0f, depth);
  if ((b & 0xe0) === 0xa0) return str(r, b & 0x1f);
  switch (b) {
    case 0xc0:
      return null;
    case 0xc2:
      return false;
    case 0xc3:
      return true;
    case 0xc4:
      return r.take(r.u8()).slice();
    case 0xc5:
      return r.take(r.u16()).slice();
    case 0xc6:
      return r.take(r.u32()).slice();
    case 0xc7:
      return ext(r, r.u8());
    case 0xc8:
      return ext(r, r.u16());
    case 0xc9:
      return ext(r, r.u32());
    case 0xca:
      return r.number("f32", 4);
    case 0xcb:
      return r.number("f64", 8);
    case 0xcc:
      return r.u8();
    case 0xcd:
      return r.u16();
    case 0xce:
      return r.u32();
    case 0xcf:
      return r.big(false);
    case 0xd0:
      return r.number("i8", 1);
    case 0xd1:
      return r.number("i16", 2);
    case 0xd2:
      return r.number("i32", 4);
    case 0xd3:
      return r.big(true);
    case 0xd4:
      return ext(r, 1);
    case 0xd5:
      return ext(r, 2);
    case 0xd6:
      return ext(r, 4);
    case 0xd7:
      return ext(r, 8);
    case 0xd8:
      return ext(r, 16);
    case 0xd9:
      return str(r, r.u8());
    case 0xda:
      return str(r, r.u16());
    case 0xdb:
      return str(r, r.u32());
    case 0xdc:
      return readArray(r, r.u16(), depth);
    case 0xdd:
      return readArray(r, r.u32(), depth);
    case 0xde:
      return readMap(r, r.u16(), depth);
    case 0xdf:
      return readMap(r, r.u32(), depth);
    default:
      throw new MsgPackError(`Unknown MessagePack byte 0x${b.toString(16)}`);
  }
}

function str(r: Reader, n: number): string {
  try {
    return decoder.decode(r.take(n));
  } catch (e) {
    if (e instanceof MsgPackError) throw e;
    throw new MsgPackError("Invalid UTF-8 in MessagePack string");
  }
}

function readArray(r: Reader, n: number, depth: number): MsgValue[] {
  const out: MsgValue[] = [];
  for (let i = 0; i < n; i++) out.push(read(r, depth + 1));
  return out;
}

function readMap(r: Reader, n: number, depth: number): MsgMap {
  // A null prototype keeps keys like "__proto__" from reaching Object.prototype.
  const out = Object.create(null) as MsgMap;
  for (let i = 0; i < n; i++) {
    const key = read(r, depth + 1);
    if (typeof key !== "string" && typeof key !== "number") throw new MsgPackError("Unsupported MessagePack map key");
    out[String(key)] = read(r, depth + 1);
  }
  return out;
}

function ext(r: Reader, n: number): MsgValue {
  const type = r.number("i8", 1);
  const data = r.take(n);
  if (type !== -1) return { ext: type, data: data.slice() };
  // The timestamp extension, which .NET uses for DateTime values.
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  if (n === 4) return new Date(view.getUint32(0) * 1000);
  if (n === 8) {
    const hi = view.getUint32(0);
    const nanos = hi >>> 2;
    const seconds = (hi & 0x3) * 2 ** 32 + view.getUint32(4);
    return new Date(seconds * 1000 + Math.floor(nanos / 1e6));
  }
  if (n === 12) {
    const nanos = view.getUint32(0);
    const seconds = Number(view.getBigInt64(4));
    return new Date(seconds * 1000 + Math.floor(nanos / 1e6));
  }
  throw new MsgPackError("Malformed MessagePack timestamp");
}

/**
 * Splits a SignalR binary payload into its messages: each is prefixed with
 * its length as a VarInt (7 bits per byte, low bits first, at most 5 bytes).
 */
export function splitSignalRFrames(bytes: Uint8Array, maxMessage = 1 << 20): Uint8Array[] {
  const out: Uint8Array[] = [];
  let pos = 0;
  while (pos < bytes.length) {
    let length = 0;
    let shift = 0;
    for (;;) {
      if (pos >= bytes.length) throw new MsgPackError("Truncated SignalR length prefix");
      if (shift > 28) throw new MsgPackError("SignalR length prefix is too long");
      const b = bytes[pos++]!;
      length += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }
    if (length > maxMessage) throw new MsgPackError("SignalR message is too large");
    if (pos + length > bytes.length) throw new MsgPackError("Truncated SignalR message");
    out.push(bytes.subarray(pos, pos + length));
    pos += length;
  }
  return out;
}
