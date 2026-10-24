import { describe, expect, it } from "vitest";
import vectors from "./fixtures/vectors.json";
import {
  CryptoError,
  decryptBytes,
  decryptString,
  deriveMasterKey,
  encryptString,
  hashMasterPassword,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  validateKdf,
  ValueFingerprinter,
} from "../src/bw/crypto";
import { fromBase64, toBase64 } from "../src/bw/encoding";

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
});

describe("KDF bounds", () => {
  it("refuses downgraded or abusive parameters", () => {
    expect(() => validateKdf({ type: KdfType.PBKDF2, iterations: 1 })).toThrow();
    expect(() => validateKdf({ type: KdfType.PBKDF2, iterations: 1e9 })).toThrow();
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 3, memory: 4096, parallelism: 4 })).toThrow();
    expect(() => validateKdf({ type: KdfType.Argon2id, iterations: 1, memory: 64, parallelism: 4 })).toThrow();
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
