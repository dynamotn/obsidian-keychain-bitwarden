// End-to-end tests against a real Vaultwarden, cross-checked with rbw (an
// independent Bitwarden client written in Rust). Run with:
//   BW_IT_URL=http://127.0.0.1:18080 npm run test:integration

import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fetchHttpClient } from "../../src/bw/http";
import { KdfType } from "../../src/bw/crypto";
import { makeDevice } from "../helpers/device";
import { registerAccount, type TestAccount } from "./account";
import { startTlsProxy, type TlsProxy } from "./tls-proxy";

const URL_ = process.env.BW_IT_URL;
const hasRbw = (() => {
  try {
    execFileSync("rbw", ["--version"]);
    return true;
  } catch {
    return false;
  }
})();
const execFileAsync = promisify(execFile);
const bwBin = fileURLToPath(new URL("../../node_modules/.bin/bw", import.meta.url));
const bin = (name: string) => fileURLToPath(new URL(`./bin/${name}`, import.meta.url));

describe.skipIf(!URL_)("against Vaultwarden", () => {
  let account: TestAccount;
  const profile = `bwsecrets-it-${process.pid}`;

  const rbw = (args: string[], extraEnv: Record<string, string> = {}) =>
    execFileSync("rbw", args, {
      env: {
        ...process.env,
        RBW_PROFILE: profile,
        BW_IT_PASSWORD: account.password,
        EDITOR: bin("fake-editor.mjs"),
        VISUAL: bin("fake-editor.mjs"),
        ...extraEnv,
      },
      encoding: "utf8",
    }).trimEnd();

  beforeAll(async () => {
    account = await registerAccount(URL_!);
    if (hasRbw) {
      rbw(["config", "set", "email", account.email]);
      rbw(["config", "set", "base_url", URL_!]);
      rbw(["config", "set", "pinentry", bin("fake-pinentry.mjs")]);
      rbw(["login"]);
    }
  }, 120_000);

  const device = async (vaultName = "notes") => {
    const d = makeDevice(fetchHttpClient, account, { serverUrl: URL_!, vaultName });
    await d.controller.unlock(account.password);
    return d;
  };

  it("uploads from one device and delivers to another", async () => {
    const a = await device();
    const b = await device();
    a.store.set("openai-api-key", "sk-live-1\nsecond line");
    a.controller.queueUpload("openai-api-key", { kind: "global" });
    expect((await a.controller.sync()).created).toEqual(["openai-api-key"]);
    expect((await b.controller.sync()).pulled).toContain("openai-api-key");
    expect(b.store.get("openai-api-key")).toBe("sk-live-1\nsecond line");
  });

  it("detects a concurrent edit through the server's revision check", async () => {
    const a = await device();
    const b = await device();
    a.store.set("race-key", "v1");
    a.controller.queueUpload("race-key", { kind: "global" });
    await a.controller.sync();
    await b.controller.sync();

    b.store.set("race-key", "from-b");
    await b.controller.sync();
    // A has not seen B's edit; its push carries a stale lastKnownRevisionDate.
    a.store.set("race-key", "from-a");
    const r = await a.controller.sync();
    expect(r.errors).toEqual([]);
    expect(r.conflicts.map((c) => c.id)).toContain("race-key");
    expect(a.store.get("race-key")).toBe("from-a");
  });

  it("works with an Argon2id account", async () => {
    const argon = await registerAccount(URL_!, { type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 4 });
    const d = makeDevice(fetchHttpClient, argon, { serverUrl: URL_! });
    await d.controller.unlock(argon.password);
    d.store.set("argon-key", "a");
    d.controller.queueUpload("argon-key", { kind: "global" });
    expect((await d.controller.sync()).created).toEqual(["argon-key"]);
  });

  describe.skipIf(!hasRbw)("interoperability with rbw (reader)", () => {
    it("rbw reads what the plugin wrote", async () => {
      const a = await device();
      a.store.set("from-plugin", "plugin value ✓");
      a.controller.queueUpload("from-plugin", { kind: "global" });
      await a.controller.sync();
      rbw(["sync"]);
      expect(rbw(["get", "--folder", "obsidian", "from-plugin"])).toBe("plugin value ✓");
    });
  });

  describe("interoperability with the official Bitwarden CLI", () => {
    let session = "";
    let proxy: TlsProxy;
    const appData = mkdtempSync(join(tmpdir(), "bw-cli-it-"));
    // Async on purpose: the TLS proxy runs in this process and must keep serving.
    const bw = async (args: string[]) =>
      (
        await execFileAsync(bwBin, args, {
        env: {
          ...process.env,
          BITWARDENCLI_APPDATA_DIR: appData,
          BW_CLIENTID: account.clientId,
          BW_CLIENTSECRET: account.clientSecret,
          BW_IT_PASSWORD: account.password,
          BW_SESSION: session,
          NODE_EXTRA_CA_CERTS: proxy.caFile,
          NODE_NO_WARNINGS: "1",
        },
          encoding: "utf8",
        })
      ).stdout.trim();

    beforeAll(async () => {
      proxy = await startTlsProxy(URL_!);
      await bw(["config", "server", proxy.url]);
      await bw(["login", "--apikey"]);
      session = await bw(["unlock", "--passwordenv", "BW_IT_PASSWORD", "--raw"]);
      // Make sure the folder exists (the plugin creates it on first upload).
      const a = await device();
      a.store.set("seed", "s");
      a.controller.queueUpload("seed", { kind: "global" });
      await a.controller.sync();
      await bw(["sync"]);
    }, 120_000);

    afterAll(() => proxy?.close());

    const folderId = async () => (JSON.parse(await bw(["list", "folders", "--search", "obsidian"])) as { id: string }[])[0]!.id;

    it("reads and edits a login created by the official client, keeping its history", async () => {
      const item = {
        type: 1,
        name: "github-token",
        folderId: await folderId(),
        notes: "some notes",
        login: { username: "me", password: "ghp_original", uris: [{ uri: "https://github.com", match: null }] },
        fields: [{ type: 1, name: "unrelated", value: "keep me" }],
      };
      const created = JSON.parse(await bw(["create", "item", Buffer.from(JSON.stringify(item)).toString("base64")]));

      const a = await device();
      expect((await a.controller.sync()).pulled).toContain("github-token");
      expect(a.store.get("github-token")).toBe("ghp_original");

      a.store.set("github-token", "ghp_rotated");
      expect((await a.controller.sync()).pushed).toEqual(["github-token"]);

      await bw(["sync"]);
      const after = JSON.parse(await bw(["get", "item", created.id]));
      expect(after.login.password).toBe("ghp_rotated");
      expect(after.login.username).toBe("me");
      expect(after.login.uris[0].uri).toBe("https://github.com");
      expect(after.notes).toBe("some notes");
      expect(after.fields).toEqual([expect.objectContaining({ name: "unrelated", value: "keep me" })]);
      expect(after.passwordHistory.map((h: { password: string }) => h.password)).toContain("ghp_original");
    });

    it("the official client can read and edit what the plugin wrote", async () => {
      const a = await device();
      a.store.set("plugin-note", "line 1\nline 2");
      a.controller.queueUpload("plugin-note", { kind: "vault", name: "notes" });
      await a.controller.sync();
      await bw(["sync"]);
      const item = (JSON.parse(await bw(["list", "items", "--search", "plugin-note"])) as Record<string, any>[])[0]!;
      expect(item.notes).toBe("line 1\nline 2");
      expect(item.fields).toContainEqual(expect.objectContaining({ name: "obsidian-scope", value: "vault:notes" }));

      item.notes = "edited in bw";
      await bw(["edit", "item", item.id, Buffer.from(JSON.stringify(item)).toString("base64")]);
      expect((await a.controller.sync()).pulled).toEqual(["plugin-note"]);
      expect(a.store.get("plugin-note")).toBe("edited in bw");
    });

    it("decrypts items that use per-item keys", async () => {
      // Recent official clients encrypt new items with their own key when the server allows it.
      const raw = JSON.parse(await bw(["get", "item", JSON.parse(await bw(["list", "items", "--search", "github-token"]))[0].id]));
      const a = await device();
      await a.controller.sync();
      expect(a.store.get("github-token")).toBe(raw.login.password);
    });
  });
});
