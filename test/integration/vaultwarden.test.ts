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
import { fetchHttpClient } from "../helpers/fetchHttp";
import { KdfType } from "../../src/bw/crypto";
import { NotificationHub, type SocketLike } from "../../src/bw/notifications";
import { makeDevice, type TestDevice } from "../helpers/device";
import {
  createOrganization,
  createOrganizationNote,
  readOrganizationNote,
  registerAccount,
  type TestAccount,
} from "./account";
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

  it("syncs an organization item both ways, keeping it in its organization", async () => {
    const org = await createOrganization(URL_!, account);
    const cipherId = await createOrganizationNote(URL_!, account, org, "team-token", "from the team");
    const d = makeDevice(fetchHttpClient, account, {
      serverUrl: URL_!,
      settings: { syncOrganizations: true },
    });
    await d.controller.unlock(account.password);
    const first = await d.controller.sync();
    expect(first.errors).toEqual([]);
    // The account is shared with the other tests, whose secrets are pulled too.
    expect(first.pulled).toContain("team-token");
    expect(d.store.get("team-token")).toBe("from the team");

    d.store.set("team-token", "edited in Obsidian");
    const second = await d.controller.sync();
    expect(second.errors).toEqual([]);
    expect(second.pushed).toEqual(["team-token"]);
    expect(await readOrganizationNote(URL_!, account, org, cipherId)).toEqual({
      organizationId: org.id,
      notes: "edited in Obsidian",
    });
  });

  it("hears about a change made on another device through the notifications hub", async () => {
    const a = await device();
    const b = await device();
    const heard: string[] = [];
    const hubFor = (name: string, d: TestDevice) =>
      new NotificationHub({
        url: () => d.controller.notificationsHubUrl(),
        createSocket: (u) => new WebSocket(u) as unknown as SocketLike,
        deviceId: () => d.controller.deviceId(),
        onChange: () => heard.push(name),
        timers: { set: (fn, ms) => setTimeout(fn, ms) as unknown as number, clear: (id) => clearTimeout(id) },
        settleMs: 100,
        minIntervalMs: 0,
      });
    const until = async (cond: () => boolean, what: string) => {
      for (let i = 0; i < 100 && !cond(); i++) await new Promise((r) => setTimeout(r, 50));
      if (!cond()) throw new Error(`timed out waiting for ${what}`);
    };
    const hubA = hubFor("a", a);
    const hubB = hubFor("b", b);
    try {
      hubA.start();
      hubB.start();
      await until(() => hubA.connected && hubB.connected, "both hubs to connect");
      b.store.set("live-key", "pushed live");
      b.controller.queueUpload("live-key", { kind: "global" });
      await b.controller.sync();
      await until(() => heard.includes("a"), "device A to hear about the change");
      // Give B's hub the same time: its own change must not come back to it.
      await new Promise((r) => setTimeout(r, 1_000));
      expect(heard.filter((h) => h === "b")).toEqual([]);
      expect((await a.controller.sync()).pulled).toContain("live-key");
    } finally {
      hubA.stop();
      hubB.stop();
    }
  });

  it.each(["xaes256gcm", "xchacha20poly1305"] as const)("syncs an account on the newer %s encryption", async (alg) => {
    const v2 = await registerAccount(URL_!, { type: KdfType.PBKDF2, iterations: 600_000 }, alg);
    const deviceOf = async () => {
      const d = makeDevice(fetchHttpClient, v2, { serverUrl: URL_! });
      await d.controller.unlock(v2.password);
      return d;
    };
    const a = await deviceOf();
    const b = await deviceOf();
    a.store.set("v2-key", "written as COSE");
    a.controller.queueUpload("v2-key", { kind: "global" });
    expect((await a.controller.sync()).created).toEqual(["v2-key"]);
    expect((await b.controller.sync()).pulled).toEqual(["v2-key"]);
    expect(b.store.get("v2-key")).toBe("written as COSE");
    b.store.set("v2-key", "edited on B");
    expect((await b.controller.sync()).pushed).toEqual(["v2-key"]);
    expect((await a.controller.sync()).pulled).toEqual(["v2-key"]);
    expect(a.store.get("v2-key")).toBe("edited on B");
    // What reached the server really is type 7.
    const sync = (await (await fetch(`${URL_}/api/sync`, { headers: { Authorization: `Bearer ${v2.accessToken}` } })).json()) as {
      ciphers: { notes: string | null; name: string; fields: { name: string; value: string | null }[] }[];
      folders: { name: string }[];
    };
    const isV2 = (s: string | null) => s === null || s.startsWith("7.");
    expect(sync.ciphers.every((c) => c.name.startsWith("7.") && isV2(c.notes))).toBe(true);
    expect(sync.ciphers.every((c) => c.fields.length > 0 && c.fields.every((f) => isV2(f.name) && isV2(f.value)))).toBe(true);
    expect(sync.folders.every((f) => f.name.startsWith("7."))).toBe(true);
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
      // rbw's agent loads organization keys only when it unlocks; earlier tests
      // add an organization, so make it unlock again (through the fake pinentry).
      rbw(["lock"]);
      expect(rbw(["get", "--folder", "obsidian", "--field", "obsidian:password", "from-plugin"])).toBe("plugin value ✓");
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
        fields: [
          { type: 0, name: "obsidian:id", value: "github-token" },
          { type: 1, name: "unrelated", value: "keep me" },
        ],
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
      expect(after.fields).toEqual([
        expect.objectContaining({ name: "obsidian:id", value: "github-token" }),
        expect.objectContaining({ name: "unrelated", value: "keep me" }),
      ]);
      expect(after.passwordHistory.map((h: { password: string }) => h.password)).toContain("ghp_original");
    });

    it("uses an obsidian:password field of an item made by the official client, leaving its password alone", async () => {
      const item = {
        type: 1,
        name: "Database",
        login: { username: "admin", password: "site-password", uris: [] },
        fields: [
          { type: 0, name: "obsidian:id", value: "db-token" },
          { type: 1, name: "obsidian:password", value: "token-1" },
        ],
      };
      const created = JSON.parse(await bw(["create", "item", Buffer.from(JSON.stringify(item)).toString("base64")]));

      const a = await device();
      expect((await a.controller.sync()).pulled).toContain("db-token");
      expect(a.store.get("db-token")).toBe("token-1");

      a.store.set("db-token", "token-2");
      expect((await a.controller.sync()).pushed).toEqual(["db-token"]);
      await bw(["sync"]);
      const after = JSON.parse(await bw(["get", "item", created.id]));
      expect(after.login.password).toBe("site-password");
      expect(after.fields).toContainEqual(expect.objectContaining({ name: "obsidian:password", value: "token-2", type: 1 }));
    });

    it("the official client can read and edit what the plugin wrote", async () => {
      const a = await device();
      a.store.set("plugin-note", "line 1\nline 2");
      a.controller.queueUpload("plugin-note", { kind: "vault", name: "notes" });
      await a.controller.sync();
      await bw(["sync"]);
      const item = (JSON.parse(await bw(["list", "items", "--search", "plugin-note"])) as Record<string, any>[])[0]!;
      // New secrets live in their own field and leave the notes to the user.
      expect(item.notes ?? null).toBeNull();
      const field = (item.fields as { name: string; value: string; type: number }[]).find((f) => f.name === "obsidian:password")!;
      expect(field).toMatchObject({ value: "line 1\nline 2", type: 1 });
      expect(item.fields).toContainEqual(expect.objectContaining({ name: "obsidian:scope", value: "vault:notes" }));

      field.value = "edited in bw";
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
