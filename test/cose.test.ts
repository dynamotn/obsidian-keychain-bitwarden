import { describe, expect, it } from "vitest";
import sdk from "./fixtures/cose-vectors.json";
import { xaes256gcmDecrypt, xaes256gcmEncrypt } from "../src/bw/aead";
import { CborError, decodeCbor, encodeCbor } from "../src/bw/cbor";
import { encodeCoseKey, pad, parseCoseKey, unpad } from "../src/bw/cose";
import {
  AccountPrivateKey,
  CryptoError,
  decryptBytes,
  decryptString,
  deriveMasterKey,
  encryptBytes,
  encryptString,
  KdfType,
  stretchMasterKey,
  SymmetricKey,
  unwrapKey,
  wrapKey,
} from "../src/bw/crypto";
import { fromBase64, toBase64, utf8Encode } from "../src/bw/encoding";

const hex = (s: string) => new Uint8Array(s.match(/../g)!.map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");

describe("XAES-256-GCM (C2SP test vectors)", () => {
  // https://c2sp.org/XAES-256-GCM; the two vectors take both branches of the CMAC subkey.
  const nonce = utf8Encode("ABCDEFGHIJKLMNOPQRSTUVWX");
  const plaintext = utf8Encode("XAES-256-GCM");
  it.each([
    [1, "", "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"],
    [3, "c2sp.org/XAES-256-GCM", "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"],
  ])("key 0x%i…", async (byte, aad, expected) => {
    const key = new Uint8Array(32).fill(byte);
    const ct = await xaes256gcmEncrypt(key, nonce, plaintext, utf8Encode(aad));
    expect(toHex(ct)).toBe(expected);
    expect(await xaes256gcmDecrypt(key, nonce, ct, utf8Encode(aad))).toEqual(plaintext);
    ct[0]! ^= 1;
    await expect(xaes256gcmDecrypt(key, nonce, ct, utf8Encode(aad))).rejects.toThrow(CryptoError);
  });
});

for (const account of sdk.accounts) {
  describe(`EncString type 7, ${account.name} (vectors from Bitwarden's SDK)`, () => {
    const userKey = () => SymmetricKey.fromBytes(fromBase64(account.userKey));

    it("unlocks the account key with the master password", async () => {
      const mk = await deriveMasterKey(sdk.password, sdk.email, { type: KdfType.PBKDF2, iterations: sdk.pbkdf2Iterations });
      const key = await unwrapKey(account.protectedUserKey, await stretchMasterKey(mk));
      expect(key.isCose).toBe(true);
      expect(toBase64(key.exportBytes())).toBe(account.userKey);
    });

    it("encodes COSE keys byte for byte like the SDK", async () => {
      const sdkBytes = unpad(fromBase64(account.userKey));
      expect(toHex(encodeCoseKey(parseCoseKey(sdkBytes)))).toBe(toHex(sdkBytes));
    });

    it("decrypts strings, padded or not", async () => {
      const key = await userKey();
      for (const t of account.texts) expect(await decryptString(t.enc, key)).toBe(t.plain);
    });

    it("unwraps legacy and COSE item keys, and decrypts with them", async () => {
      const key = await userKey();
      for (const k of account.itemKeys) {
        const itemKey = await unwrapKey(k.wrapped, key);
        expect(itemKey.isCose).toBe(k.kind === "cose");
        expect(toBase64(itemKey.exportBytes())).toBe(k.key);
        expect(await decryptString(k.field, itemKey)).toBe(k.fieldPlain);
      }
    });

    it("unwraps the private key, which then reads organization keys", async () => {
      const priv = await AccountPrivateKey.unwrap(account.privateKey.wrapped, await userKey());
      // Wrap a key to the matching public key and read it back through the unwrapped private key.
      const pub = await crypto.subtle.importKey("spki", fromBase64(account.privateKey.spki), { name: "RSA-OAEP", hash: "SHA-1" }, false, [
        "encrypt",
      ]);
      const orgKey = crypto.getRandomValues(new Uint8Array(64));
      const wrapped = `4.${toBase64(new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pub, orgKey)))}`;
      expect(await priv.decrypt(wrapped)).toEqual(orgKey);
    });

    it("round-trips what the plugin encrypts", async () => {
      const key = await userKey();
      for (const plain of ["", "x", "y".repeat(31), "z".repeat(32), "Tiếng Việt 🙂\n".repeat(20)]) {
        const enc = await encryptString(plain, key);
        expect(enc.startsWith("7.")).toBe(true);
        expect(await decryptString(enc, key)).toBe(plain);
      }
      const item = await SymmetricKey.generate();
      expect(toBase64((await unwrapKey(await wrapKey(item, key), key)).exportBytes())).toBe(toBase64(item.exportBytes()));
    });

    it("refuses a message for another key or of another kind", async () => {
      const key = await userKey();
      const other = sdk.accounts.find((a) => a !== account)!;
      const otherKey = await SymmetricKey.fromBytes(fromBase64(other.userKey));
      const sameAlgDifferentKey = await SymmetricKey.generate(key.algorithm);
      const enc = account.texts[1]!.enc;
      await expect(decryptString(enc, otherKey)).rejects.toThrow(/different key type/);
      await expect(decryptString(enc, sameAlgDifferentKey)).rejects.toThrow(/different key/);
      await expect(decryptString(enc, await SymmetricKey.generate())).rejects.toThrow(/legacy key/);
      // A wrapped key is not a string, and a string is not a key.
      await expect(decryptString(account.itemKeys[0]!.wrapped, key)).rejects.toThrow(/holds legacy-key data/);
      await expect(unwrapKey(enc, key)).rejects.toThrow(/holds utf8 data/);
      await expect(decryptBytes(enc, key)).rejects.toThrow(/holds utf8 data/);
    });

    it("refuses tampered messages", async () => {
      const key = await userKey();
      const message = fromBase64(account.texts[1]!.enc.slice(2));
      const [prot, unprot, ct] = decodeCbor(message) as [Uint8Array, Map<number, unknown>, Uint8Array];
      const encode = (p: Uint8Array, c: Uint8Array) => `7.${toBase64(encodeCbor([p, unprot as never, c]))}`;
      const flipped = ct.slice();
      flipped[flipped.length - 1]! ^= 1;
      await expect(decryptString(encode(prot, flipped), key)).rejects.toThrow(/tampered/);
      // Same header fields, re-encoded: the AAD covers the exact header bytes.
      const header = decodeCbor(prot) as Map<number, unknown>;
      header.set(3, "application/x.bitwarden.legacy-key");
      await expect(unwrapKey(encode(encodeCbor(header as never), ct), key)).rejects.toThrow(/tampered/);
      header.set(2, [1]);
      await expect(decryptString(encode(encodeCbor(header as never), ct), key)).rejects.toThrow(/critical/);
      await expect(decryptString(`7.${toBase64(new Uint8Array([0xd0, ...message]))}`, key)).rejects.toThrow(/Malformed/);
      await expect(decryptString("7.!!!", key)).rejects.toThrow(/Malformed/);
      await expect(decryptString(`7.${toBase64(message.subarray(0, 20))}`, key)).rejects.toThrow(/Malformed/);
    });
  });
}

describe("COSE keys", () => {
  it("only allow the operations they list", async () => {
    const bytes = unpad(fromBase64(sdk.accounts[0]!.userKey));
    const k = parseCoseKey(bytes);
    const decryptOnly = SymmetricKey.fromCoseKey(encodeCoseKey({ ...k, keyOps: [4] }));
    const encryptOnly = SymmetricKey.fromCoseKey(encodeCoseKey({ ...k, keyOps: [3] }));
    await expect(encryptString("x", decryptOnly)).rejects.toThrow(/may not be used to encrypt/);
    await expect(decryptString(sdk.accounts[0]!.texts[1]!.enc, encryptOnly)).rejects.toThrow(/may not be used to decrypt/);
  });

  it("reject malformed keys", () => {
    const k = parseCoseKey(unpad(fromBase64(sdk.accounts[0]!.userKey)));
    const bad = (changes: Record<number, unknown>) => {
      const m = new Map<number, unknown>([[1, 4], [2, k.keyId], [3, -70010], [4, k.keyOps], [-1, k.key]]);
      for (const [label, v] of Object.entries(changes)) m.set(Number(label), v);
      return () => SymmetricKey.fromCoseKey(encodeCbor(m as never));
    };
    expect(bad({ 1: 1 })).toThrow(/symmetric/);
    expect(bad({ 3: 1 })).toThrow(/algorithm/); // AES-GCM keys are not used for EncStrings
    expect(bad({ 2: new Uint8Array(4) })).toThrow(/key id/);
    expect(bad({ [-1]: new Uint8Array(16) })).toThrow(/key/);
    expect(bad({ 4: [9] })).toThrow(/operations/);
  });

  it("use the SDK's padding", () => {
    expect([...pad(new Uint8Array([7, 7]), 4)]).toEqual([7, 7, 2, 2]);
    expect([...pad(new Uint8Array([7, 7, 7, 7]), 4)]).toEqual([7, 7, 7, 7, 1]);
    expect([...unpad(new Uint8Array([7, 7, 2, 2]))]).toEqual([7, 7]);
    expect(() => unpad(new Uint8Array([7, 0]))).toThrow(CryptoError);
    expect(() => unpad(new Uint8Array([7, 9]))).toThrow(CryptoError);
    expect(() => unpad(new Uint8Array([]))).toThrow(CryptoError);
  });

  it("keep their kind when remembered", async () => {
    for (const alg of ["xaes256gcm", "xchacha20poly1305"] as const) {
      const key = await SymmetricKey.generate(alg);
      const back = await SymmetricKey.fromBytes(key.exportBytes());
      expect(back.algorithm).toBe(alg);
      expect(await decryptString(await encryptString("v", key), back)).toBe("v");
      expect((await encryptBytes(new Uint8Array([1]), key, "pkcs8")).startsWith("7.")).toBe(true);
    }
  });
});

describe("CBOR decoder", () => {
  it.each([
    ["an indefinite-length array", "9f01ff"],
    ["a tag", "c001"],
    ["trailing bytes", "0101"],
    ["a truncated byte string", "4301"],
    ["a duplicate map key", "a2010101 02".replace(/\s/g, "").replace("0102", "0101")],
    ["a float", "f93c00"],
    ["invalid UTF-8", "62c328"],
    ["an array map key", "a18001"],
  ])("rejects %s", (_name, bytes) => {
    expect(() => decodeCbor(hex(bytes))).toThrow(CborError);
  });

  it("rejects deep nesting", () => {
    expect(() => decodeCbor(new Uint8Array(100).fill(0x81))).toThrow(/nested/);
  });

  it("round-trips the values COSE uses", () => {
    const v = [new Uint8Array([1, 2]), new Map<number | string, never>([[1, -70010 as never], [3, "text" as never]]), -1, 2 ** 40, true, null];
    expect(decodeCbor(encodeCbor(v as never))).toEqual(v);
    expect(toHex(encodeCbor(-70010))).toBe("3a00011179");
  });
});
