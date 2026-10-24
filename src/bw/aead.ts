// The two AEADs Bitwarden uses for COSE EncStrings (type 7), both with a
// 256-bit key and a 192-bit nonce, and a 16-byte tag after the ciphertext.
//
// - XAES-256-GCM (https://c2sp.org/XAES-256-GCM): built here on WebCrypto,
//   which has AES-GCM natively; only the per-nonce key derivation is extra.
// - XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha): from @noble/ciphers, as
//   WebCrypto has no ChaCha20.

import { xchacha20poly1305 } from "@noble/ciphers/chacha.js";
import { CryptoError } from "./crypto-error";

export const NONCE_SIZE = 24;
const KEY_SIZE = 32;

const subtle = crypto.subtle;

function check(key: Uint8Array, nonce: Uint8Array) {
  if (key.length !== KEY_SIZE) throw new CryptoError("AEAD keys are 32 bytes");
  if (nonce.length !== NONCE_SIZE) throw new CryptoError("AEAD nonces are 24 bytes");
}

/** AES-256 of one block: the first block of AES-CBC with a zero IV is exactly that. */
async function aesBlock(key: CryptoKey, block: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const out = await subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, block);
  return new Uint8Array(out, 0, 16).slice();
}

/** The XAES-256-GCM derived key for one nonce: SP 800-108 counter KDF with CMAC-AES256. */
async function xaesDerive(key: Uint8Array<ArrayBuffer>, nonce: Uint8Array): Promise<CryptoKey> {
  const k = await subtle.importKey("raw", key, "AES-CBC", false, ["encrypt"]);
  const l = await aesBlock(k, new Uint8Array(16));
  // K1 = L << 1, reduced by the GF(2^128) polynomial when the top bit falls off.
  const k1 = new Uint8Array(16);
  for (let i = 0; i < 16; i++) k1[i] = ((l[i]! << 1) | (i < 15 ? l[i + 1]! >> 7 : 0)) & 0xff;
  if (l[0]! & 0x80) k1[15]! ^= 0x87;
  const derived = new Uint8Array(32);
  for (const counter of [1, 2]) {
    const m = new Uint8Array(16);
    m.set([0x00, counter, 0x58, 0x00]);
    m.set(nonce.subarray(0, 12), 4);
    for (let i = 0; i < 16; i++) m[i]! ^= k1[i]!;
    derived.set(await aesBlock(k, m), (counter - 1) * 16);
  }
  try {
    return await subtle.importKey("raw", derived, "AES-GCM", false, ["encrypt", "decrypt"]);
  } finally {
    derived.fill(0);
    l.fill(0);
    k1.fill(0);
  }
}

export async function xaes256gcmEncrypt(
  key: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  check(key, nonce);
  const k = await xaesDerive(key, nonce);
  const iv = nonce.slice(12);
  return new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad }, k, plaintext));
}

export async function xaes256gcmDecrypt(
  key: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  check(key, nonce);
  const k = await xaesDerive(key, nonce);
  try {
    return new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: nonce.slice(12), additionalData: aad }, k, ciphertext));
  } catch {
    throw new CryptoError("Decryption failed (wrong key or tampered data)");
  }
}

export function xchacha20poly1305Encrypt(
  key: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  plaintext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  check(key, nonce);
  return new Uint8Array(xchacha20poly1305(key, nonce, aad).encrypt(plaintext));
}

export function xchacha20poly1305Decrypt(
  key: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  ciphertext: Uint8Array<ArrayBuffer>,
  aad: Uint8Array<ArrayBuffer>,
): Uint8Array<ArrayBuffer> {
  check(key, nonce);
  try {
    return new Uint8Array(xchacha20poly1305(key, nonce, aad).decrypt(ciphertext));
  } catch {
    throw new CryptoError("Decryption failed (wrong key or tampered data)");
  }
}
