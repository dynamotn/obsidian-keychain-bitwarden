// Bitwarden client-side cryptography, implemented on WebCrypto plus a WASM
// Argon2id so that it runs unchanged on every Obsidian platform.
//
// Only the "2" EncString type (AES-256-CBC with HMAC-SHA256, encrypt-then-MAC)
// is accepted. Unauthenticated legacy types are refused on purpose.

import { argon2InThread, KdfAbortedError, type Argon2Runner } from "./argon2";
import { concatBytes, fromBase64, toBase64, utf8Decode, utf8Encode } from "./encoding";

const subtle = crypto.subtle;

export const KdfType = { PBKDF2: 0, Argon2id: 1 } as const;

export type KdfParams =
  | { type: typeof KdfType.PBKDF2; iterations: number }
  | { type: typeof KdfType.Argon2id; iterations: number; memory: number; parallelism: number };

export class CryptoError extends Error {
  override name = "CryptoError";
}

// Bounds follow the ranges the Bitwarden clients accept. The lower bounds stop
// a hostile server from downgrading the KDF; the upper bounds stop it from
// freezing a phone with an absurd work factor.
export function validateKdf(kdf: KdfParams): void {
  const inRange = (v: number, lo: number, hi: number) => Number.isInteger(v) && v >= lo && v <= hi;
  if (kdf.type === KdfType.PBKDF2) {
    if (!inRange(kdf.iterations, 5_000, 2_000_000)) {
      throw new CryptoError(`PBKDF2 iterations out of range: ${kdf.iterations}`);
    }
    return;
  }
  if (kdf.type === KdfType.Argon2id) {
    if (!inRange(kdf.iterations, 2, 10)) throw new CryptoError(`Argon2 iterations out of range: ${kdf.iterations}`);
    if (!inRange(kdf.memory, 16, 1024)) throw new CryptoError(`Argon2 memory out of range: ${kdf.memory} MiB`);
    if (!inRange(kdf.parallelism, 1, 16)) throw new CryptoError(`Argon2 parallelism out of range: ${kdf.parallelism}`);
    return;
  }
  throw new CryptoError(`Unsupported KDF type: ${String((kdf as { type: unknown }).type)}`);
}

export interface DeriveOptions {
  /** Where Argon2id runs; the calling thread by default. */
  argon2?: Argon2Runner;
  /** Stops the derivation (a worker is terminated; the calling thread only checks between steps). */
  signal?: AbortSignal;
}

/** Derives the 32-byte master key from the master password. */
export async function deriveMasterKey(
  password: string,
  email: string,
  kdf: KdfParams,
  { argon2 = argon2InThread, signal }: DeriveOptions = {},
): Promise<Uint8Array<ArrayBuffer>> {
  validateKdf(kdf);
  if (signal?.aborted) throw new KdfAbortedError();
  const salt = utf8Encode(email.trim().toLowerCase());
  const pw = utf8Encode(password);
  try {
    if (kdf.type === KdfType.PBKDF2) {
      const key = await pbkdf2(pw, salt, kdf.iterations);
      if (signal?.aborted) {
        key.fill(0);
        throw new KdfAbortedError();
      }
      return key;
    }
    return await argon2(
      {
        password: pw,
        salt: new Uint8Array(await subtle.digest("SHA-256", salt)),
        iterations: kdf.iterations,
        memoryKiB: kdf.memory * 1024,
        parallelism: kdf.parallelism,
      },
      signal,
    );
  } finally {
    pw.fill(0);
  }
}

async function pbkdf2(password: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, iterations: number) {
  const base = await subtle.importKey("raw", password, "PBKDF2", false, ["deriveBits"]);
  const bits = await subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations }, base, 256);
  return new Uint8Array(bits);
}

/** The hash the server stores for password logins; only needed by tests and registration. */
export async function hashMasterPassword(masterKey: Uint8Array<ArrayBuffer>, password: string): Promise<string> {
  return toBase64(await pbkdf2(masterKey, utf8Encode(password), 1));
}

async function hmacSign(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const k = await subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await subtle.sign("HMAC", k, data));
}

/** HKDF-Expand (RFC 5869) for a single 32-byte block, as Bitwarden uses it. */
async function hkdfExpand32(prk: Uint8Array<ArrayBuffer>, info: string): Promise<Uint8Array<ArrayBuffer>> {
  return hmacSign(prk, concatBytes(utf8Encode(info), new Uint8Array([1])));
}

/** A 64-byte Bitwarden symmetric key: 32 bytes AES key followed by 32 bytes HMAC key. */
export class SymmetricKey {
  private constructor(
    private raw: Uint8Array<ArrayBuffer>,
    readonly encKey: CryptoKey,
    readonly macKey: CryptoKey,
  ) {}

  static async fromBytes(bytes: Uint8Array): Promise<SymmetricKey> {
    if (bytes.length !== 64) throw new CryptoError(`Expected a 64-byte key, got ${bytes.length} bytes`);
    const raw = new Uint8Array(bytes);
    const encKey = await subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["encrypt", "decrypt"]);
    const macKey = await subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    return new SymmetricKey(raw, encKey, macKey);
  }

  static async generate(): Promise<SymmetricKey> {
    return SymmetricKey.fromBytes(crypto.getRandomValues(new Uint8Array(64)));
  }

  /** Raw key material, for the opt-in "remember on this device" setting. */
  exportBytes(): Uint8Array<ArrayBuffer> {
    if (this.raw.length === 0) throw new CryptoError("Key has been wiped");
    return new Uint8Array(this.raw);
  }

  /** A sub-key for purposes outside Bitwarden's own formats, domain-separated by `purpose`. */
  async deriveSubKey(purpose: string): Promise<Uint8Array<ArrayBuffer>> {
    return hkdfExpand32(this.exportBytes().slice(32), `obsidian-keychain-bitwarden:${purpose}`);
  }

  /** Best-effort zeroing; the CryptoKey objects are non-extractable and are dropped with this object. */
  wipe(): void {
    this.raw.fill(0);
    this.raw = new Uint8Array(0);
  }
}

/** Turns the master key into the key that protects the user key. */
export async function stretchMasterKey(masterKey: Uint8Array<ArrayBuffer>): Promise<SymmetricKey> {
  const enc = await hkdfExpand32(masterKey, "enc");
  const mac = await hkdfExpand32(masterKey, "mac");
  return SymmetricKey.fromBytes(concatBytes(enc, mac));
}

interface ParsedEncString {
  iv: Uint8Array<ArrayBuffer>;
  data: Uint8Array<ArrayBuffer>;
  mac: Uint8Array<ArrayBuffer>;
}

function parseEncString(value: string): ParsedEncString {
  const dot = value.indexOf(".");
  const type = dot > 0 ? value.slice(0, dot) : "";
  if (type !== "2") {
    throw new CryptoError(
      type === "7"
        ? "This vault uses the newer COSE encryption format, which is not supported yet"
        : `Unsupported or unauthenticated encryption type "${type || "?"}"`,
    );
  }
  const parts = value.slice(dot + 1).split("|");
  if (parts.length !== 3) throw new CryptoError("Malformed encrypted string");
  let iv: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>, mac: Uint8Array<ArrayBuffer>;
  try {
    [iv, data, mac] = parts.map(fromBase64) as [Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>];
  } catch {
    throw new CryptoError("Malformed encrypted string");
  }
  if (iv.length !== 16 || mac.length !== 32 || data.length === 0 || data.length % 16 !== 0) {
    throw new CryptoError("Malformed encrypted string");
  }
  return { iv, data, mac };
}

export async function decryptBytes(value: string, key: SymmetricKey): Promise<Uint8Array<ArrayBuffer>> {
  const { iv, data, mac } = parseEncString(value);
  // subtle.verify compares in constant time; decrypting only after it passes
  // keeps the CBC padding oracle out of reach.
  const ok = await subtle.verify("HMAC", key.macKey, mac, concatBytes(iv, data));
  if (!ok) throw new CryptoError("MAC verification failed (wrong password or tampered data)");
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-CBC", iv }, key.encKey, data));
  } catch {
    throw new CryptoError("Decryption failed");
  }
}

export async function decryptString(value: string, key: SymmetricKey): Promise<string> {
  return utf8Decode(await decryptBytes(value, key));
}

export async function encryptBytes(plain: Uint8Array<ArrayBuffer>, key: SymmetricKey): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const data = new Uint8Array(await subtle.encrypt({ name: "AES-CBC", iv }, key.encKey, plain));
  const mac = new Uint8Array(await subtle.sign("HMAC", key.macKey, concatBytes(iv, data)));
  return `2.${toBase64(iv)}|${toBase64(data)}|${toBase64(mac)}`;
}

export async function encryptString(plain: string, key: SymmetricKey): Promise<string> {
  return encryptBytes(utf8Encode(plain), key);
}

/**
 * The account's RSA private key, used only to unwrap organization keys.
 * Bitwarden wraps those with RSA-OAEP: EncString type 4 (SHA-1, what the
 * clients use) or type 3 (SHA-256).
 */
export class AccountPrivateKey {
  private constructor(private readonly der: Uint8Array<ArrayBuffer>) {}

  /** Decrypts `profile.privateKey` (a PKCS#8 key under the user key). */
  static async unwrap(encrypted: string, userKey: SymmetricKey): Promise<AccountPrivateKey> {
    return new AccountPrivateKey(await decryptBytes(encrypted, userKey));
  }

  async decrypt(value: string): Promise<Uint8Array<ArrayBuffer>> {
    const dot = value.indexOf(".");
    const type = dot > 0 ? value.slice(0, dot) : "";
    const hash = type === "4" ? "SHA-1" : type === "3" ? "SHA-256" : null;
    if (!hash) throw new CryptoError(`Unsupported organization key type "${type || "?"}"`);
    let data: Uint8Array<ArrayBuffer>;
    try {
      data = fromBase64(value.slice(dot + 1));
    } catch {
      throw new CryptoError("Malformed organization key");
    }
    let key: CryptoKey;
    try {
      key = await subtle.importKey("pkcs8", this.der, { name: "RSA-OAEP", hash }, false, ["decrypt"]);
    } catch {
      throw new CryptoError("The account's private key cannot be read");
    }
    try {
      return new Uint8Array(await subtle.decrypt({ name: "RSA-OAEP" }, key, data));
    } catch {
      throw new CryptoError("Organization key decryption failed");
    }
  }

  wipe(): void {
    this.der.fill(0);
  }
}

/**
 * Keyed fingerprint of a secret value, used to notice local edits without
 * storing the value or a plain (brute-forceable) hash of it.
 */
export class ValueFingerprinter {
  private constructor(private readonly key: CryptoKey) {}

  static async forUserKey(userKey: SymmetricKey): Promise<ValueFingerprinter> {
    const sub = await userKey.deriveSubKey("value-fingerprint");
    const key = await subtle.importKey("raw", sub, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return new ValueFingerprinter(key);
  }

  async of(id: string, value: string): Promise<string> {
    const sig = await subtle.sign("HMAC", this.key, utf8Encode(`${id}\u0000${value}`));
    return toBase64(new Uint8Array(sig));
  }
}
