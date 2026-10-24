// A CBOR (RFC 8949) codec, just enough for the COSE objects Bitwarden uses:
// COSE_Encrypt0 messages and COSE_Key keys. Input comes from the server, so
// every read is bounds-checked, nesting is limited, and only definite-length
// items without tags are accepted, which is all Bitwarden's SDK produces.

export type CborValue = number | bigint | string | Uint8Array | boolean | null | CborValue[] | CborMap;
/** Integer and text keys are kept apart, as CBOR does. */
export type CborMap = Map<number | string, CborValue>;

export class CborError extends Error {
  override name = "CborError";
}

const MAX_DEPTH = 16;
const utf8 = new TextDecoder("utf-8", { fatal: true });

class Reader {
  pos = 0;
  constructor(private readonly bytes: Uint8Array) {}
  private need(n: number) {
    if (n < 0 || this.pos + n > this.bytes.length) throw new CborError("Truncated CBOR data");
  }
  u8() {
    this.need(1);
    return this.bytes[this.pos++]!;
  }
  take(n: number) {
    this.need(n);
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  /** The argument of a head byte; lengths and integers up to 2^64-1. */
  argument(info: number): number | bigint {
    if (info < 24) return info;
    const size = info === 24 ? 1 : info === 25 ? 2 : info === 26 ? 4 : info === 27 ? 8 : 0;
    if (!size) throw new CborError("Indefinite lengths and reserved values are not supported");
    const b = this.take(size);
    let v = 0n;
    for (const x of b) v = (v << 8n) | BigInt(x);
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v;
  }
  length(info: number): number {
    const n = this.argument(info);
    if (typeof n !== "number") throw new CborError("CBOR item is too long");
    return n;
  }
}

/** Decodes one CBOR item that must fill `bytes` exactly. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const r = new Reader(bytes);
  const value = read(r, 0);
  if (r.pos !== bytes.length) throw new CborError("Trailing bytes after CBOR item");
  return value;
}

function read(r: Reader, depth: number): CborValue {
  if (depth > MAX_DEPTH) throw new CborError("CBOR data is nested too deeply");
  const head = r.u8();
  const major = head >> 5;
  const info = head & 0x1f;
  switch (major) {
    case 0:
      return r.argument(info);
    case 1: {
      const n = r.argument(info);
      return typeof n === "number" ? -1 - n : -1n - n;
    }
    case 2:
      return r.take(r.length(info)).slice();
    case 3:
      try {
        return utf8.decode(r.take(r.length(info)));
      } catch (e) {
        if (e instanceof CborError) throw e;
        throw new CborError("Invalid UTF-8 in CBOR text");
      }
    case 4: {
      const n = r.length(info);
      const out: CborValue[] = [];
      for (let i = 0; i < n; i++) out.push(read(r, depth + 1));
      return out;
    }
    case 5: {
      const n = r.length(info);
      const out: CborMap = new Map();
      for (let i = 0; i < n; i++) {
        const key = read(r, depth + 1);
        if (typeof key !== "number" && typeof key !== "string") throw new CborError("Unsupported CBOR map key");
        if (out.has(key)) throw new CborError("Duplicate CBOR map key");
        out.set(key, read(r, depth + 1));
      }
      return out;
    }
    case 6:
      throw new CborError("CBOR tags are not supported");
    default:
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new CborError("Unsupported CBOR simple value or float");
  }
}

/** Encodes in the preferred (shortest) form, map entries in the order given. */
export function encodeCbor(value: CborValue): Uint8Array<ArrayBuffer> {
  const out: number[] = [];
  write(out, value);
  return new Uint8Array(out);
}

function head(out: number[], major: number, n: number | bigint) {
  const v = BigInt(n);
  // Callers never pass a negative argument; a bigint of 2^64 or more would be truncated.
  if (v < 0n || v >= 1n << 64n) throw new CborError("CBOR argument out of range");
  if (v < 24n) out.push((major << 5) | Number(v));
  else if (v < 0x100n) out.push((major << 5) | 24, Number(v));
  else if (v < 0x10000n) out.push((major << 5) | 25, Number(v >> 8n), Number(v & 0xffn));
  else if (v < 0x100000000n) {
    out.push((major << 5) | 26);
    for (let s = 24n; s >= 0n; s -= 8n) out.push(Number((v >> s) & 0xffn));
  } else {
    out.push((major << 5) | 27);
    for (let s = 56n; s >= 0n; s -= 8n) out.push(Number((v >> s) & 0xffn));
  }
}

function write(out: number[], value: CborValue) {
  if (value === null) out.push(0xf6);
  else if (value === true) out.push(0xf5);
  else if (value === false) out.push(0xf4);
  else if (typeof value === "number" || typeof value === "bigint") {
    if (typeof value === "number" && !Number.isSafeInteger(value)) throw new CborError("Only integers are supported");
    const v = BigInt(value);
    if (v >= 0n) head(out, 0, v);
    else head(out, 1, -1n - v);
  } else if (typeof value === "string") {
    const b = new TextEncoder().encode(value);
    head(out, 3, b.length);
    for (const x of b) out.push(x);
  } else if (value instanceof Uint8Array) {
    head(out, 2, value.length);
    for (const x of value) out.push(x);
  } else if (Array.isArray(value)) {
    head(out, 4, value.length);
    for (const v of value) write(out, v);
  } else {
    head(out, 5, value.size);
    for (const [k, v] of value) {
      write(out, k);
      write(out, v);
    }
  }
}
