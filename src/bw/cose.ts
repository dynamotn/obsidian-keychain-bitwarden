// COSE objects as Bitwarden's SDK (bitwarden-crypto) defines them: symmetric
// COSE_Key keys and COSE_Encrypt0 messages, which are EncString type 7.
//
// Reference: sdk-internal, crates/bitwarden-crypto/src/cose and
// enc_string/symmetric.rs. Known-answer vectors made with that SDK are in
// test/fixtures/cose-vectors.json.

import { xaes256gcmDecrypt, xaes256gcmEncrypt, xchacha20poly1305Decrypt, xchacha20poly1305Encrypt, NONCE_SIZE } from "./aead";
import { decodeCbor, encodeCbor, type CborMap, type CborValue } from "./cbor";
import { CryptoError } from "./crypto-error";

export type CoseAlgorithm = "xaes256gcm" | "xchacha20poly1305";

// Private-use COSE algorithm values from the SDK (cose/mod.rs).
const ALG: Record<CoseAlgorithm, number> = { xchacha20poly1305: -70000, xaes256gcm: -70010 };

// COSE header labels (RFC 9052) and key parameters (RFC 9053).
const H_ALG = 1;
const H_CRIT = 2;
const H_CONTENT_TYPE = 3;
const H_KID = 4;
const H_IV = 5;
const K_KTY = 1;
const K_KID = 2;
const K_ALG = 3;
const K_OPS = 4;
const K_SYMMETRIC_KEY = -1;
const KTY_SYMMETRIC = 4;

export const KEY_ID_SIZE = 16;
const KEY_SIZE = 32;

export const KeyOp = { Encrypt: 3, Decrypt: 4, WrapKey: 5, UnwrapKey: 6 } as const;
const ALL_OPS: number[] = [KeyOp.Decrypt, KeyOp.Encrypt, KeyOp.WrapKey, KeyOp.UnwrapKey];

/** What a COSE message holds, authenticated in its protected header. */
export type ContentFormat = "utf8" | "legacy-key" | "cose-key" | "pkcs8" | "octet-stream";

const CONTENT_TYPE: Record<ContentFormat, string | number> = {
  utf8: "application/x.bitwarden.utf8-padded",
  "legacy-key": "application/x.bitwarden.legacy-key",
  "cose-key": 101, // CoAP content format application/cose-key
  pkcs8: 284, // application/pkcs8
  "octet-stream": 42,
};

function contentFormatOf(value: CborValue | undefined): ContentFormat {
  for (const [format, v] of Object.entries(CONTENT_TYPE) as [ContentFormat, string | number][]) {
    if (v === value) return format;
  }
  throw new CryptoError("COSE message has a missing or unsupported content type");
}

/** A symmetric COSE key, as stored inside a COSE_Key. */
export interface CoseKeyMaterial {
  algorithm: CoseAlgorithm;
  keyId: Uint8Array<ArrayBuffer>;
  keyOps: number[];
  key: Uint8Array<ArrayBuffer>;
}

function algorithmOf(value: CborValue | undefined): CoseAlgorithm {
  for (const [name, v] of Object.entries(ALG) as [CoseAlgorithm, number][]) if (v === value) return name;
  throw new CryptoError("Unsupported COSE algorithm");
}

function bytesField(map: CborMap, label: number, size: number, what: string): Uint8Array<ArrayBuffer> {
  const v = map.get(label);
  if (!(v instanceof Uint8Array) || v.length !== size) throw new CryptoError(`COSE ${what} is missing or malformed`);
  return new Uint8Array(v);
}

function asMap(value: CborValue, what: string): CborMap {
  if (!(value instanceof Map)) throw new CryptoError(`Malformed COSE ${what}`);
  return value;
}

function decode(bytes: Uint8Array, what: string): CborValue {
  try {
    return decodeCbor(bytes);
  } catch {
    // decodeCbor only throws CborError: every read is bounds-checked.
    throw new CryptoError(`Malformed COSE ${what}`);
  }
}

export function parseCoseKey(bytes: Uint8Array): CoseKeyMaterial {
  const map = asMap(decode(bytes, "key"), "key");
  if (map.get(K_KTY) !== KTY_SYMMETRIC) throw new CryptoError("COSE key is not a symmetric key");
  const ops = map.get(K_OPS) ?? [];
  if (!Array.isArray(ops) || !ops.every((op) => ALL_OPS.includes(op as number))) {
    throw new CryptoError("COSE key has unsupported key operations");
  }
  return {
    algorithm: algorithmOf(map.get(K_ALG)),
    keyId: bytesField(map, K_KID, KEY_ID_SIZE, "key id"),
    keyOps: ops as number[],
    key: bytesField(map, K_SYMMETRIC_KEY, KEY_SIZE, "key"),
  };
}

export function encodeCoseKey(k: CoseKeyMaterial): Uint8Array<ArrayBuffer> {
  // Same order as coset: kty, kid, alg, key_ops, then the key itself.
  return encodeCbor(
    new Map<number, CborValue>([
      [K_KTY, KTY_SYMMETRIC],
      [K_KID, k.keyId],
      [K_ALG, ALG[k.algorithm]],
      [K_OPS, k.keyOps],
      [K_SYMMETRIC_KEY, k.key],
    ]),
  );
}

export function generateCoseKey(algorithm: CoseAlgorithm): CoseKeyMaterial {
  return {
    algorithm,
    keyId: crypto.getRandomValues(new Uint8Array(KEY_ID_SIZE)),
    keyOps: [...ALL_OPS],
    key: crypto.getRandomValues(new Uint8Array(KEY_SIZE)),
  };
}

// --- Padding (keys/utils.rs): the last N bytes hold N, at least one byte ---------

export function pad(bytes: Uint8Array, minLength: number): Uint8Array<ArrayBuffer> {
  const n = Math.max(minLength - bytes.length, 1);
  if (n > 255) throw new CryptoError("Padding too long");
  const out = new Uint8Array(bytes.length + n);
  out.set(bytes);
  out.fill(n, bytes.length);
  return out;
}

export function unpad(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const n = bytes[bytes.length - 1] ?? 0;
  if (n === 0 || n > bytes.length) throw new CryptoError("Invalid padding");
  return new Uint8Array(bytes.subarray(0, bytes.length - n));
}

/** Strings are padded to the next multiple of 32 bytes, to hide their exact length. */
const TEXT_BLOCK = 32;

// --- COSE_Encrypt0 -----------------------------------------------------------------

function encStructure(protectedBytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return encodeCbor(["Encrypt0", protectedBytes, new Uint8Array(0)]);
}

function requireOp(k: CoseKeyMaterial, op: number, what: string) {
  if (!k.keyOps.includes(op)) throw new CryptoError(`This key may not be used to ${what}`);
}

/** Encrypts into the bytes of a COSE_Encrypt0, as EncString type 7 carries them. */
export async function coseEncrypt(
  k: CoseKeyMaterial,
  plaintext: Uint8Array<ArrayBuffer>,
  format: ContentFormat,
): Promise<Uint8Array<ArrayBuffer>> {
  requireOp(k, KeyOp.Encrypt, "encrypt");
  const protectedBytes = encodeCbor(
    new Map<number, CborValue>([
      [H_ALG, ALG[k.algorithm]],
      [H_CONTENT_TYPE, CONTENT_TYPE[format]],
      [H_KID, k.keyId],
    ]),
  );
  const data = format === "utf8" ? pad(plaintext, TEXT_BLOCK * (1 + Math.floor(plaintext.length / TEXT_BLOCK))) : plaintext;
  const nonce = crypto.getRandomValues(new Uint8Array(NONCE_SIZE));
  const aad = encStructure(protectedBytes);
  const ciphertext =
    k.algorithm === "xaes256gcm"
      ? await xaes256gcmEncrypt(k.key, nonce, data, aad)
      : xchacha20poly1305Encrypt(k.key, nonce, data, aad);
  return encodeCbor([protectedBytes, new Map<number, CborValue>([[H_IV, nonce]]), ciphertext]);
}

/**
 * Authenticates and decrypts a COSE_Encrypt0. The message must name this
 * key (algorithm and key id) and carry one of the `expected` content formats,
 * so a ciphertext cannot be passed off as a different kind of value.
 */
export async function coseDecrypt(
  k: CoseKeyMaterial,
  message: Uint8Array,
  expected: readonly ContentFormat[],
): Promise<{ plaintext: Uint8Array<ArrayBuffer>; format: ContentFormat }> {
  requireOp(k, KeyOp.Decrypt, "decrypt");
  const parts = decode(message, "message");
  if (!Array.isArray(parts) || parts.length !== 3) throw new CryptoError("Malformed COSE message");
  const [protectedBytes, unprotected, ciphertext] = parts;
  if (!(protectedBytes instanceof Uint8Array) || !(ciphertext instanceof Uint8Array)) {
    throw new CryptoError("Malformed COSE message");
  }
  const header: CborMap = protectedBytes.length ? asMap(decode(protectedBytes, "header"), "header") : new Map<number | string, CborValue>();
  if (header.has(H_CRIT)) throw new CryptoError("COSE message has critical headers this client does not know");
  if (algorithmOf(header.get(H_ALG)) !== k.algorithm) throw new CryptoError("COSE message is for a different key type");
  const kid = header.get(H_KID);
  if (!(kid instanceof Uint8Array) || kid.length !== k.keyId.length || !kid.every((b, i) => b === k.keyId[i])) {
    throw new CryptoError("COSE message was encrypted with a different key");
  }
  const format = contentFormatOf(header.get(H_CONTENT_TYPE));
  if (!expected.includes(format)) throw new CryptoError(`COSE message holds ${format} data, not ${expected.join(" or ")}`);
  const nonce = bytesField(asMap(unprotected!, "header"), H_IV, NONCE_SIZE, "nonce");
  const aad = encStructure(protectedBytes);
  const data = new Uint8Array(ciphertext);
  const plain =
    k.algorithm === "xaes256gcm"
      ? await xaes256gcmDecrypt(k.key, nonce, data, aad)
      : xchacha20poly1305Decrypt(k.key, nonce, data, aad);
  return { plaintext: format === "utf8" ? unpad(plain) : plain, format };
}
