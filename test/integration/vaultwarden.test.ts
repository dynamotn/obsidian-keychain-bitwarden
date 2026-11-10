// End-to-end tests against a real Vaultwarden, cross-checked with rbw (an
// independent Bitwarden client written in Rust). Run with:
//   BW_IT_URL=http://127.0.0.1:18080 npm run test:integration

import { execFile, execFileSync } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { STORAGE_PREFIX, type SocketLike } from "../../src/core/ports";
import { fetchHttpClient } from "../helpers/fetchHttp";
import { encryptString, KdfType } from "../helpers/bw/crypto";
import { makeDevice, type TestDevice } from "../helpers/device";
import {
  api,
  createOrganization,
  createOrganizationNote,
  readOrganizationNote,
  registerAccount,
  withSecurityState,
  type TestAccount,
} from "./account";
import { startTlsProxy, type TlsProxy } from "./tls-proxy";

// The transport is fetch with `redirect: "error"`, so the host declares that it refuses redirects and the core sends
// the API key to a self-hosted server without an acknowledgement (ADR 0018). One test runs as requestUrl does in
// Obsidian instead: redirects followed (`refusesRedirects` false), the server acknowledged on the device.
const redirects = vi.hoisted(() => ({ refused: true }));
vi.mock("../../src/core/ports", async (importOriginal) => {
  const ports = await importOriginal<typeof import("../../src/core/ports")>();
  return {
    ...ports,
    hostPorts: (deps: Parameters<typeof ports.hostPorts>[0]) => ({
      ...ports.hostPorts(deps),
      refusesRedirects: () => redirects.refused,
    }),
  };
});
const ACKNOWLEDGED = `${STORAGE_PREFIX}acknowledged-origins`;

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

  /** A device unlocked on `who`; nothing acknowledged, as the transport refuses redirects. */
  const deviceOf = async (who: TestAccount, opts: Parameters<typeof makeDevice>[2] = {}, http = fetchHttpClient) => {
    const d = makeDevice(withSecurityState(http, who), who, { serverUrl: URL_!, ...opts });
    d.localStorage.delete(ACKNOWLEDGED);
    await d.controller.unlock(who.password);
    return d;
  };
  const device = (vaultName = "notes") => deviceOf(account, { vaultName });

  it("follows redirects only for a server acknowledged on the device (ADR 0018)", async () => {
    redirects.refused = false;
    try {
      const d = makeDevice(fetchHttpClient, account, { serverUrl: URL_! });
      d.localStorage.delete(ACKNOWLEDGED);
      await expect(d.controller.unlock(account.password)).rejects.toMatchObject({ code: "origin-not-acknowledged" });
      await d.controller.acknowledgeOrigin();
      await d.controller.unlock(account.password);
      d.store.set("acknowledged-key", "through requestUrl's rules");
      await d.controller.queueUpload("acknowledged-key", { kind: "global" });
      expect((await d.controller.sync()).created).toEqual(["acknowledged-key"]);
    } finally {
      redirects.refused = true;
    }
  });

  it("uploads from one device and delivers to another", async () => {
    const a = await device();
    const b = await device();
    a.store.set("openai-api-key", "sk-live-1\nsecond line");
    await a.controller.queueUpload("openai-api-key", { kind: "global" });
    expect((await a.controller.sync()).created).toEqual(["openai-api-key"]);
    expect((await b.controller.sync()).pulled).toContain("openai-api-key");
    expect(b.store.get("openai-api-key")).toBe("sk-live-1\nsecond line");
  });

  it("detects a concurrent edit through the server's revision check", async () => {
    const a = await device();
    const b = await device();
    a.store.set("race-key", "v1");
    await a.controller.queueUpload("race-key", { kind: "global" });
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
    const d = await deviceOf(account, { settings: { syncOrganizations: true } });
    const first = await d.controller.sync();
    expect(first.errors).toEqual([]);
    // The account is shared with the other tests, whose secrets are pulled too.
    expect(first.pulled).toContain("team-token");
    expect(d.store.get("team-token")).toBe("from the team");

    d.store.set("team-token", "edited in Obsidian");
    // The first push to an organization item asks (M6: the core's organization-push conflict).
    expect((await d.controller.sync()).conflicts).toContainEqual(expect.objectContaining({ id: "team-token", kind: "organization-push" }));
    const second = await d.controller.sync(new Map([["team-token", { policy: "prefer-local", kind: "organization-push" }]]));
    expect(second.errors).toEqual([]);
    expect(second.pushed).toEqual(["team-token"]);
    expect(await readOrganizationNote(URL_!, account, org, cipherId)).toEqual({
      organizationId: org.id,
      notes: "edited in Obsidian",
    });
  });

  it("hears about a change made on another device through the notifications hub", async () => {
    const heard: string[] = [];
    let open = 0;
    // The core's hub on the plugin's socket port, over a real WebSocket.
    const createSocket = (u: string) => {
      const ws = new WebSocket(u);
      ws.addEventListener("open", () => open++);
      return ws as unknown as SocketLike;
    };
    const a = await deviceOf(account, { createSocket });
    const b = await deviceOf(account, { createSocket });
    const until = async (cond: () => boolean, what: string) => {
      for (let i = 0; i < 100 && !cond(); i++) await new Promise((r) => setTimeout(r, 50));
      if (!cond()) throw new Error(`timed out waiting for ${what}`);
    };
    const hubs = [a.controller.startHub(() => heard.push("a")), b.controller.startHub(() => heard.push("b"))];
    try {
      await until(() => open === 2, "both hubs to connect");
      // The handshake follows the open.
      await new Promise((r) => setTimeout(r, 500));
      b.store.set("live-key", "pushed live");
      await b.controller.queueUpload("live-key", { kind: "global" });
      await b.controller.sync();
      await until(() => heard.includes("a"), "device A to hear about the change");
      // Give B's hub the same time: its own change must not come back to it.
      await new Promise((r) => setTimeout(r, 1_000));
      expect(heard.filter((h) => h === "b")).toEqual([]);
      expect((await a.controller.sync()).pulled).toContain("live-key");
    } finally {
      a.controller.stopHub();
      b.controller.stopHub();
      await Promise.all(hubs);
    }
  });

  // Security state version 1: new items are written field by field, which Vaultwarden takes (see the blob test below).
  it.each(["xaes256gcm", "xchacha20poly1305"] as const)("syncs an account on the newer %s encryption", async (alg) => {
    const v2 = await registerAccount(URL_!, { type: KdfType.PBKDF2, iterations: 600_000 }, alg, 1);
    const a = await deviceOf(v2);
    const b = await deviceOf(v2);
    a.store.set("v2-key", "written as COSE");
    await a.controller.queueUpload("v2-key", { kind: "global" });
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
    const d = await deviceOf(argon);
    d.store.set("argon-key", "a");
    await d.controller.queueUpload("argon-key", { kind: "global" });
    expect((await d.controller.sync()).created).toEqual(["argon-key"]);
  });

  // Two answers only a real server gives (M6 Task 9 review). No bitwarden.com account is at hand: Vaultwarden
  // answers here, and both answers are refusals the core has to handle (dybw-core follow-ups, not plugin patches).
  it("pushes to an item the server sends without its secure note part: Vaultwarden refuses the push", async () => {
    const enc = (s: string) => encryptString(s, account.userKey);
    // Vaultwarden does not store a secure note without its part ("Data missing"): the item is made whole, and the
    // device is shown it without the part, as a server that drops it would.
    const created = (await api(account, URL_!, "POST", "/ciphers", {
      type: 2,
      folderId: null,
      organizationId: null,
      favorite: false,
      reprompt: 0,
      secureNote: { type: 0 },
      name: await enc("bare note"),
      notes: await enc("first"),
      fields: [{ type: 0, name: await enc("obsidian:id"), value: await enc("bare-note") }],
      encryptedFor: account.userId,
    })) as { id: string };
    const sent: unknown[] = [];
    const bare: typeof fetchHttpClient = async (req) => {
      if (req.method === "PUT" && req.url.includes(created.id)) sent.push((JSON.parse(req.body!) as { secureNote?: unknown }).secureNote);
      const res = await fetchHttpClient(req);
      if (!res.text.includes(created.id)) return res;
      const body = JSON.parse(res.text) as { ciphers?: { id: string; secureNote?: unknown }[] };
      for (const c of body.ciphers ?? []) if (c.id === created.id) c.secureNote = null;
      return { ...res, text: JSON.stringify(body) };
    };
    const a = await deviceOf(account, {}, bare);
    expect((await a.controller.sync()).pulled).toContain("bare-note");
    a.store.set("bare-note", "second");
    const r = await a.controller.sync();
    // The core sends the part as it got it (null); Vaultwarden answers 400. Nothing is lost: the value stays here,
    // the item stays as it was.
    expect(sent).toEqual([null]);
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual([{ id: "bare-note", error: expect.stringMatching(/^HTTP 400 .*Data missing/) }]);
    expect(a.store.get("bare-note")).toBe("second");
    expect(await api(account, URL_!, "GET", `/ciphers/${created.id}`)).toMatchObject({ secureNote: { type: 0 } });
  });

  it("writes a new item of a COSE account at security version 2 as a blob: Vaultwarden refuses it at any size", async () => {
    const v2 = await registerAccount(URL_!, { type: KdfType.PBKDF2, iterations: 600_000 }, "xchacha20poly1305");
    const writes: [string, number][] = [];
    const a = await deviceOf(v2, {}, async (req) => {
      const res = await fetchHttpClient(req);
      if (req.method === "POST" && req.url.endsWith("/api/ciphers")) writes.push([JSON.parse(req.body!).data ? "blob" : "fields", res.status]);
      return res;
    });
    // Short, then as long as the notes take; past that the core refuses before sending anything.
    for (const [size, error] of [[10, "HTTP 422"], [9_900, "HTTP 422"], [10_001, "the value is too long for a Bitwarden item"]] as const) {
      a.store.set(`big-key-${size}`, "x".repeat(size));
      await a.controller.queueUpload(`big-key-${size}`, { kind: "global" });
      const r = await a.controller.sync();
      expect(r.created).toEqual([]);
      expect(r.errors).toContainEqual({ id: `big-key-${size}`, error });
    }
    expect(writes.every(([shape, status]) => shape === "blob" && status === 422)).toBe(true);
    // Still queued: the next sync tries again.
    expect(await a.controller.uploadCandidates()).toEqual([]);
  });

  describe.skipIf(!hasRbw)("interoperability with rbw (reader)", () => {
    it("rbw reads what the plugin wrote", async () => {
      const a = await device();
      a.store.set("from-plugin", "plugin value ✓");
      await a.controller.queueUpload("from-plugin", { kind: "global" });
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
      await a.controller.queueUpload("seed", { kind: "global" });
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
      // ADR 0016: the first write-back into a login's own password asks first.
      expect((await a.controller.sync()).questions).toEqual([expect.objectContaining({ id: "github-token", question: "first-write-back" })]);
      const answer = { question: "first-write-back", answer: "write-to-login" } as const;
      expect((await a.controller.sync(undefined, new Map([["github-token", answer]]))).pushed).toEqual(["github-token"]);

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
      await a.controller.queueUpload("plugin-note", { kind: "vault", name: "notes" });
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

    it("puts a value too long for a field into the notes, readable by the official client", async () => {
      const long = "-----BEGIN KEY-----\n" + "k".repeat(4_000) + "\n-----END KEY-----";
      const a = await device();
      a.store.set("long-key", long);
      await a.controller.queueUpload("long-key", { kind: "global" });
      expect((await a.controller.sync()).errors).toEqual([]);
      await bw(["sync"]);
      const item = (JSON.parse(await bw(["list", "items", "--search", "long-key"])) as Record<string, any>[])[0]!;
      expect(item.notes).toBe(long);
      expect(item.fields).toContainEqual(expect.objectContaining({ name: "obsidian:location", value: "notes" }));
      expect(item.fields.map((f: { name: string }) => f.name)).not.toContain("obsidian:password");
      const b = await device();
      await b.controller.sync();
      expect(b.store.get("long-key")).toBe(long);
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
