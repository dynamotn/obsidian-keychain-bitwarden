import { describe, expect, it, vi } from "vitest";
import vectors from "./fixtures/vectors.json";
import { KdfAbortedError } from "../src/bw/argon2";
import {
  AccountPrivateKey,
  CryptoError,
  decryptBytes,
  decryptString,
  deriveMasterKey,
  encryptBytes,
  encryptString,
  hashMasterPassword,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  unwrapKey,
  validateKdf,
  ValueFingerprinter,
  wrapKey,
} from "../src/bw/crypto";
import { concatBytes, fromBase64, toBase64 } from "../src/bw/encoding";

// Vectors come from an independent Python implementation (fixtures/gen_vectors.py).
describe("key derivation (known answers)", () => {
  it("PBKDF2 master key, stretched key and password hash", async () => {
    const mk = await deriveMasterKey(vectors.password, vectors.email, {
      type: KdfType.PBKDF2,
      iterations: vectors.pbkdf2.iterations,
    });
    expect(toBase64(mk)).toBe(vectors.pbkdf2.masterKey);
    expect(toBase64((await stretchMasterKey(mk)).exportBytes())).toBe(vectors.pbkdf2.stretched);
    expect(await hashMasterPassword(mk, vectors.password)).toBe(vectors.pbkdf2.masterPasswordHash);
  });

  it("Argon2id master key and stretched key", async () => {
    const a = vectors.argon2id;
    const mk = await deriveMasterKey(vectors.password, vectors.email, {
      type: KdfType.Argon2id,
      iterations: a.iterations,
      memory: a.memory,
      parallelism: a.parallelism,
    });
    expect(toBase64(mk)).toBe(a.masterKey);
    expect(toBase64((await stretchMasterKey(mk)).exportBytes())).toBe(a.stretched);
  });
});

describe("EncString", () => {
  it("decrypts the protected user key with the stretched key", async () => {
    const stretched = await SymmetricKey.fromBytes(fromBase64(vectors.pbkdf2.stretched));
    expect(toBase64(await decryptBytes(vectors.protectedUserKey, stretched))).toBe(vectors.userKey);
  });

  it("decrypts reference ciphertexts and round-trips its own", async () => {
    const key = await SymmetricKey.fromBytes(fromBase64(vectors.userKey));
    for (const v of vectors.encStrings) {
      expect(await decryptString(v.enc, key)).toBe(v.plain);
      expect(await decryptString(await encryptString(v.plain, key), key)).toBe(v.plain);
    }
  });

  it("uses a fresh IV for every encryption", async () => {
    const key = await SymmetricKey.generate();
    expect(await encryptString("same", key)).not.toBe(await encryptString("same", key));
  });

  it("rejects tampered data, wrong keys and unauthenticated types", async () => {
    const key = await SymmetricKey.fromBytes(fromBase64(vectors.userKey));
    const enc = vectors.encStrings[2]!.enc;
    const [iv, ct, mac] = enc.slice(2).split("|") as [string, string, string];
    const ctBytes = fromBase64(ct);
    ctBytes[0]! ^= 1;
    await expect(decryptString(`2.${iv}|${toBase64(ctBytes)}|${mac}`, key)).rejects.toThrow(/MAC/);
    await expect(decryptString(enc, await SymmetricKey.generate())).rejects.toThrow(/MAC/);
    await expect(decryptString(`0.${iv}|${ct}`, key)).rejects.toThrow(CryptoError);
    await expect(decryptString(`7.abc`, key)).rejects.toThrow(/COSE/);
    await expect(decryptString(`2.${iv}|${ct}`, key)).rejects.toThrow(/Malformed/);
    await expect(decryptString(`2.!!|${ct}|${mac}`, key)).rejects.toThrow(/Malformed/);
  });

  it("names no type when the string has none", async () => {
    const key = await SymmetricKey.fromBytes(fromBase64(vectors.userKey));
    for (const value of ["no-dot", ".starts-with-a-dot"]) {
      await expect(decryptString(value, key)).rejects.toThrow('Unsupported or unauthenticated encryption type "?"');
    }
  });

  it("rejects type 2 parts of the wrong size before checking the MAC", async () => {
    const key = await SymmetricKey.fromBytes(fromBase64(vectors.userKey));
    const b64 = (n: number) => toBase64(new Uint8Array(n));
    // Each would otherwise fail the MAC check; the message tells them apart.
    for (const [iv, data, mac] of [
      [15, 16, 32],
      [16, 16, 31],
      [16, 0, 32],
      [16, 17, 32],
    ]) {
      await expect(decryptBytes(`2.${b64(iv!)}|${b64(data!)}|${b64(mac!)}`, key)).rejects.toThrow("Malformed encrypted string");
    }
  });

  it("reports data that passes the MAC but does not decrypt", async () => {
    const raw = fromBase64(vectors.userKey);
    const key = await SymmetricKey.fromBytes(raw);
    const encKey = await crypto.subtle.importKey("raw", raw.slice(0, 32), "AES-CBC", false, ["encrypt"]);
    const macKey = await crypto.subtle.importKey("raw", raw.slice(32), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    // The first block of a zero plaintext alone decrypts to a final byte of 0: invalid PKCS#7 padding.
    const iv = new Uint8Array(16);
    const data = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, encKey, new Uint8Array(16))).slice(0, 16);
    const mac = new Uint8Array(await crypto.subtle.sign("HMAC", macKey, concatBytes(iv, data)));
    const value = `2.${toBase64(iv)}|${toBase64(data)}|${toBase64(mac)}`;
    await expect(decryptBytes(value, key)).rejects.toThrow(CryptoError);
    await expect(decryptBytes(value, key)).rejects.toThrow(/^Decryption failed$/);
  });

  it("refuses legacy data under a COSE key", async () => {
    const coseKey = await SymmetricKey.generate("xaes256gcm");
    await expect(decryptString(vectors.encStrings[0]!.enc, coseKey)).rejects.toThrow(/legacy format, but the key is a COSE key/);
  });
});

describe("key wrapping", () => {
  it("wraps a COSE key under a COSE key as a COSE key", async () => {
    const wrapping = await SymmetricKey.generate("xchacha20poly1305");
    const key = await SymmetricKey.generate("xaes256gcm");
    const wrapped = await wrapKey(key, wrapping);
    const back = await unwrapKey(wrapped, wrapping);
    expect(back.isCose).toBe(true);
    expect(toBase64(back.exportBytes())).toBe(toBase64(key.exportBytes()));
    await expect(decryptBytes(wrapped, wrapping)).rejects.toThrow(/holds cose-key data/);
  });

  it("has no COSE form for a legacy key", async () => {
    const key = await SymmetricKey.generate();
    expect(() => key.coseKeyBytes()).toThrow(/Not a COSE key/);
  });
});

describe("AccountPrivateKey", () => {
  it("reports a private key that is not PKCS#8", async () => {
    const userKey = await SymmetricKey.generate();
    const priv = await AccountPrivateKey.unwrap(await encryptBytes(new Uint8Array([1, 2, 3]), userKey, "pkcs8"), userKey);
    await expect(priv.decrypt("4.AAAA")).rejects.toThrow("The account's private key cannot be read");
  });
});

describe("cancelling the key derivation", () => {
  const pbkdf2 = { type: KdfType.PBKDF2, iterations: 5_000 } as const;

  it("does not start when already cancelled", async () => {
    const abort = new AbortController();
    abort.abort();
    const argon2 = vi.fn(async () => new Uint8Array(32));
    const argonKdf = { type: KdfType.Argon2id, iterations: 2, memory: 16, parallelism: 1 } as const;
    await expect(deriveMasterKey("pw", "a@b.c", argonKdf, { argon2, signal: abort.signal })).rejects.toBeInstanceOf(
      KdfAbortedError,
    );
    expect(argon2).not.toHaveBeenCalled();
    await expect(deriveMasterKey("pw", "a@b.c", pbkdf2, { signal: abort.signal })).rejects.toBeInstanceOf(KdfAbortedError);
  });

  it("discards a PBKDF2 key cancelled while it was derived", async () => {
    const abort = new AbortController();
    const run = deriveMasterKey("pw", "a@b.c", pbkdf2, { signal: abort.signal });
    abort.abort();
    await expect(run).rejects.toBeInstanceOf(KdfAbortedError);
  });
});

describe("KDF bounds", () => {
  it("refuses downgraded or abusive parameters", () => {
    expect(() => validateKdf({ type: KdfType.PBKDF2, iterations: 1 })).toThrow();
    expect(() => validateKdf({ type: KdfType.PBKDF2, iterations: 1e9 })).toThrow();
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 3, memory: 4096, parallelism: 4 })).toThrow();
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 1, memory: 64, parallelism: 4 })).toThrow();
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 0 })).toThrow(/parallelism/);
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 17 })).toThrow(/parallelism/);
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 16 })).not.toThrow();
    expect(() => validateKdf({ type: 9 } as never)).toThrow();
    expect(() => validateKdf({ type: KdfType.PBKDF2, iterations: 600_000 })).not.toThrow();
  });
});

describe("SymmetricKey", () => {
  it("wipes its raw material", async () => {
    const key = await SymmetricKey.generate();
    key.wipe();
    expect(() => key.exportBytes()).toThrow(/wiped/);
  });

  it("rejects keys of the wrong size", async () => {
    await expect(SymmetricKey.fromBytes(new Uint8Array(32))).rejects.toThrow(/key length/);
    await expect(SymmetricKey.fromBytes(new Uint8Array(63))).rejects.toThrow(/key length/);
  });
});

describe("ValueFingerprinter", () => {
  it("is deterministic per key and binds the id", async () => {
    const k1 = await ValueFingerprinter.forUserKey(await SymmetricKey.fromBytes(fromBase64(vectors.userKey)));
    const k2 = await ValueFingerprinter.forUserKey(await SymmetricKey.generate());
    expect(await k1.of("a", "v")).toBe(await k1.of("a", "v"));
    expect(await k1.of("a", "v")).not.toBe(await k1.of("b", "v"));
    expect(await k1.of("a", "v")).not.toBe(await k2.of("a", "v"));
    // id/value boundary is unambiguous
    expect(await k1.of("a-b", "c")).not.toBe(await k1.of("a", "b-c"));
  });
});
