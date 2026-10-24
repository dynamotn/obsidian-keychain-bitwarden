// Runs in Node only (it starts cargo); not part of the browser suites.
import { execFileSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import sdk from "../fixtures/cose-vectors.json";
import { encryptString, SymmetricKey, unwrapKey, wrapKey } from "../../src/bw/crypto";
import { fromBase64, toBase64 } from "../../src/bw/encoding";

// The other direction: Bitwarden's SDK decrypts what the plugin encrypted.
// Needs Rust; run with `npm run test:sdk`.
describe.runIf(process.env.BW_SDK_VERIFY === "1")("accepted by Bitwarden's SDK", () => {
  it("decrypts strings and wrapped keys the plugin produced", async () => {
    const cases: { key: string; enc: string; plain: string }[] = [];
    for (const account of sdk.accounts) {
      const key = await SymmetricKey.fromBytes(fromBase64(account.userKey));
      for (const plain of ["", "a", "y".repeat(32), "Tiếng Việt 🙂 secret\nwith lines"]) {
        cases.push({ key: account.userKey, enc: await encryptString(plain, key), plain });
      }
      // A value under a legacy item key the plugin wrapped with the COSE user key.
      const item = await SymmetricKey.generate();
      const unwrapped = await unwrapKey(await wrapKey(item, key), key);
      cases.push({ key: toBase64(unwrapped.exportBytes()), enc: await encryptString("under an item key", item), plain: "under an item key" });
    }
    const out = execFileSync(
      "cargo",
      ["run", "--quiet", "--release", "--manifest-path", "test/fixtures/sdk-vectors/Cargo.toml", "--", "verify"],
      { input: JSON.stringify(cases), encoding: "utf8" },
    );
    expect(out).toContain(`verified ${cases.length} ciphertexts`);
  }, 600_000);
});
