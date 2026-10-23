import { beforeEach, describe, expect, it } from "vitest";
import { decryptString, SymmetricKey, decryptBytes, KdfType } from "../src/bw/crypto";
import { SECRET_USER_KEY } from "../src/controller";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";

let server: FakeBitwardenServer;
let a: TestDevice;
let b: TestDevice;

async function unlocked(device: TestDevice) {
  await device.controller.unlock(server.account.password);
  return device;
}

beforeEach(async () => {
  server = await FakeBitwardenServer.create();
  a = await unlocked(makeDevice(server.http, server.account));
  b = await unlocked(makeDevice(server.http, server.account));
});

async function remoteValue(cipherId: string): Promise<string> {
  const c = server.ciphers.find((x) => x.id === cipherId)!;
  let key = server.account.userKey;
  if (c.key) key = await SymmetricKey.fromBytes(await decryptBytes(c.key, key));
  return decryptString((c.type === 1 ? (c.login!.password as string) : c.notes)!, key);
}

describe("unlock", () => {
  it("rejects a wrong master password", async () => {
    const d = makeDevice(server.http, server.account);
    await expect(d.controller.unlock("nope")).rejects.toThrow(/MAC/);
    expect(d.controller.isUnlocked).toBe(false);
  });

  it("rejects a wrong API key", async () => {
    const d = makeDevice(server.http, { ...server.account, clientSecret: "bad" });
    await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/HTTP 400/);
  });

  it("works with Argon2id accounts", async () => {
    server = await FakeBitwardenServer.create({ type: KdfType.Argon2id, iterations: 2, memory: 16, parallelism: 1 });
    const d = makeDevice(server.http, server.account);
    await d.controller.unlock(server.account.password);
    expect(d.controller.isUnlocked).toBe(true);
  });

  it("never sends the master password or anything derived from it", async () => {
    const d = makeDevice(server.http, server.account);
    server.requests = [];
    await d.controller.unlock(server.account.password);
    const wire = JSON.stringify(server.requests);
    expect(wire).not.toContain(server.account.password);
    expect(wire).not.toContain(encodeURIComponent(server.account.password));
  });

  it("remembers the key only when asked, and drops a stale one", async () => {
    expect(a.store.get(SECRET_USER_KEY)).toBe("");
    const d = makeDevice(server.http, server.account, { settings: { rememberKey: true } });
    await d.controller.unlock(server.account.password);
    expect(d.store.get(SECRET_USER_KEY)).toMatch(/^[A-Za-z0-9+/]+=*$/);
    d.controller.lock();
    expect(await d.controller.unlockFromRememberedKey()).toBe(true);

    d.controller.lock();
    d.store.set(SECRET_USER_KEY, btoa(String.fromCharCode(...new Uint8Array(64))));
    expect(await d.controller.unlockFromRememberedKey()).toBe(false);
    expect(d.store.get(SECRET_USER_KEY)).toBe("");
  });
});

describe("sync between devices", () => {
  it("pulls items created by other Bitwarden clients, including per-item keys and logins", async () => {
    await server.addItem({ folder: "obsidian", name: "openai-api-key", value: "sk-1" });
    await server.addItem({ folder: "obsidian", name: "Anthropic", id: "anthropic-key", value: "sk-ant", itemKey: true });
    await server.addItem({ folder: "obsidian", name: "github-token", value: "ghp_x", type: 1 });
    await server.addItem({ folder: "elsewhere", name: "bank-pin", value: "1234" });
    const report = await a.controller.sync();
    expect(report.pulled.sort()).toEqual(["anthropic-key", "github-token", "openai-api-key"]);
    expect(a.store.get("anthropic-key")).toBe("sk-ant");
    expect(a.store.get("github-token")).toBe("ghp_x");
    expect(a.store.get("bank-pin")).toBeNull();
  });

  it("uploads on one device and delivers to another", async () => {
    a.store.set("openai-api-key", "sk-1");
    a.controller.queueUpload("openai-api-key", { kind: "global" });
    expect((await a.controller.sync()).created).toEqual(["openai-api-key"]);
    expect((await b.controller.sync()).pulled).toEqual(["openai-api-key"]);
    expect(b.store.get("openai-api-key")).toBe("sk-1");

    b.store.set("openai-api-key", "sk-2");
    expect((await b.controller.sync()).pushed).toEqual(["openai-api-key"]);
    expect((await a.controller.sync()).pulled).toEqual(["openai-api-key"]);
    expect(a.store.get("openai-api-key")).toBe("sk-2");
  });

  it("is idempotent", async () => {
    await server.addItem({ folder: "obsidian", name: "k", value: "v" });
    await a.controller.sync();
    const r = await a.controller.sync();
    expect([...r.pulled, ...r.pushed, ...r.created, ...r.cleared, ...r.conflicts]).toEqual([]);
  });

  it("only uploads what was explicitly queued", async () => {
    a.store.set("private-thing", "x");
    await a.controller.sync();
    expect(server.ciphers).toHaveLength(0);
    expect(a.controller.uploadCandidates()).toEqual(["private-thing"]);
  });

  it("keeps the rest of an item intact when pushing a new value", async () => {
    const login = await server.addItem({ folder: "obsidian", name: "github-token", value: "old", type: 1 });
    await a.controller.sync();
    a.store.set("github-token", "new");
    await a.controller.sync();
    const updated = server.ciphers.find((c) => c.id === login.id)!;
    expect(await remoteValue(login.id)).toBe("new");
    expect(updated.name).toBe(login.name);
    expect(updated.notes).toBe(login.notes);
    expect(updated.fields).toEqual(login.fields);
    expect(updated.login!.username).toBe(login.login!.username);
    expect(updated.passwordHistory?.[0]?.password).toBe(login.login!.password);
  });

  it("pushes through per-item keys", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "k", value: "v1", itemKey: true });
    await a.controller.sync();
    a.store.set("k", "v2");
    await a.controller.sync();
    expect(await remoteValue(c.id)).toBe("v2");
    expect(server.ciphers.find((x) => x.id === c.id)!.key).toBe(c.key);
  });

  it("reports conflicts and resolves them per secret", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "k", value: "v1" });
    await a.controller.sync();
    a.store.set("k", "local");
    await server.editValue(c.id, "remote");
    const r = await a.controller.sync();
    expect(r.conflicts).toEqual([{ id: "k", kind: "both-changed", label: "k" }]);
    expect(a.store.get("k")).toBe("local");

    await a.controller.sync(new Map([["k", { policy: "prefer-local", kind: "both-changed" }]]));
    expect(await remoteValue(c.id)).toBe("local");
  });

  it("retries when another device edits during the push", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "k", value: "v1" });
    await a.controller.sync();
    a.store.set("k", "mine");
    let raced = false;
    server.beforeUpdate = (id) => {
      if (!raced && id === c.id) {
        raced = true;
        const cur = server.ciphers.find((x) => x.id === id)!;
        cur.revisionDate = server.nextRevision();
      }
    };
    const r = await a.controller.sync();
    // Same value, newer revision: second pass sees only the local edit and pushes it.
    expect(r.passes).toBe(2);
    expect(r.pushed).toEqual(["k"]);
    expect(await remoteValue(c.id)).toBe("mine");
  });

  it("clears a secret deleted in Bitwarden", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "k", value: "v" });
    await server.addItem({ folder: "obsidian", name: "other", value: "o" });
    await a.controller.sync();
    server.ciphers.find((x) => x.id === c.id)!.deletedDate = server.nextRevision();
    expect((await a.controller.sync()).cleared).toEqual(["k"]);
    expect(a.store.get("k")).toBe("");
    expect(a.state().base.k).toBeUndefined();
  });

  it("refuses to wipe the device when the folder disappears or empties", async () => {
    await server.addItem({ folder: "obsidian", name: "k1", value: "v" });
    await server.addItem({ folder: "obsidian", name: "k2", value: "v" });
    await a.controller.sync();

    for (const c of server.ciphers) c.deletedDate = server.nextRevision();
    await expect(a.controller.sync()).rejects.toThrow(/refusing/);
    expect(a.store.get("k1")).toBe("v");

    server.folders = [];
    await expect(a.controller.sync()).rejects.toThrow(/not found/);
    expect(a.store.get("k2")).toBe("v");
  });

  it("respects vault and device scopes", async () => {
    await server.addItem({ folder: "obsidian", name: "work", value: "w", scope: "vault:work" });
    await server.addItem({ folder: "obsidian", name: "mine", value: "m", scope: `device:${a.controller.deviceId()}` });
    await server.addItem({ folder: "obsidian", name: "bad-scope", value: "x", scope: "planet:mars" });
    const w = makeDevice(server.http, server.account, { vaultName: "work" });
    await w.controller.unlock(server.account.password);
    const rw = await w.controller.sync();
    expect(rw.pulled).toEqual(["work"]);
    expect(rw.skipped.map((s) => s.reason)).toContainEqual(expect.stringMatching(/obsidian-scope/));
    expect((await a.controller.sync()).pulled).toEqual(["mine"]);
  });

  it("stores device-scoped uploads under this device's id", async () => {
    a.store.set("local-only", "x");
    a.controller.queueUpload("local-only", { kind: "device", id: "" });
    await a.controller.sync();
    expect((await b.controller.sync()).pulled).toEqual([]);
    const c = server.ciphers[0]!;
    const scopes = await Promise.all(
      (c.fields ?? []).map(async (f) => [await decryptString(f.name!, server.account.userKey), await decryptString(f.value!, server.account.userKey)]),
    );
    expect(scopes).toContainEqual(["obsidian-scope", `device:${a.controller.deviceId()}`]);
  });

  it("never lets Bitwarden overwrite the plugin's own credentials", async () => {
    await server.addItem({ folder: "obsidian", name: "bitwarden-secrets-client-secret", value: "evil" });
    const r = await a.controller.sync();
    expect(r.pulled).toEqual([]);
    expect(a.store.get("bitwarden-secrets-client-secret")).toBe(server.account.clientSecret);
  });

  it("skips undecryptable or invalid items without failing the sync", async () => {
    const bad = await server.addItem({ folder: "obsidian", name: "tampered", value: "v" });
    bad.notes = bad.notes!.replace(/\|([A-Za-z0-9+/])/, (_m, ch: string) => `|${ch === "A" ? "B" : "A"}`);
    await server.addItem({ folder: "obsidian", name: "Not A Valid Id", value: "v" });
    await server.addItem({ folder: "obsidian", name: "good", value: "g" });
    const r = await a.controller.sync();
    expect(r.pulled).toEqual(["good"]);
    expect(r.skipped).toHaveLength(2);
  });

  it("uses the newest of duplicate ids", async () => {
    await server.addItem({ folder: "obsidian", name: "dup", value: "old" });
    await server.addItem({ folder: "obsidian", name: "Dup", id: "dup", value: "new" });
    const r = await a.controller.sync();
    expect(a.store.get("dup")).toBe("new");
    expect(r.skipped.map((s) => s.reason)).toContainEqual(expect.stringMatching(/duplicate/));
  });

  it("queues a call made during a running sync instead of dropping it", async () => {
    await server.addItem({ folder: "obsidian", name: "k", value: "v" });
    server.requests = [];
    const first = a.controller.sync();
    // Queued while the first sync is in flight: must still be uploaded.
    a.store.set("late", "x");
    a.controller.queueUpload("late", { kind: "global" });
    const second = a.controller.sync();
    const third = a.controller.sync();
    const [r1, r2, r3] = await Promise.all([first, second, third]);
    expect(r1.pulled).toEqual(["k"]);
    // Picked up by whichever run planned after it was queued, never lost.
    expect([...r1.created, ...r2.created]).toEqual(["late"]);
    expect(r3).toBe(r2);
    expect(server.requests.filter((r) => r.url.endsWith("/sync?excludeDomains=true"))).toHaveLength(2);
  });

  it("keeps state per device, outside anything that gets synced", async () => {
    await server.addItem({ folder: "obsidian", name: "k", value: "v" });
    await a.controller.sync();
    expect(Object.keys(a.state().base)).toEqual(["k"]);
    expect(Object.keys(b.state().base)).toEqual([]);
    expect(JSON.stringify(a.state())).not.toContain('"v"');
  });

  // Regression tests for the security review.
  describe("audit regressions", () => {
    it("keeps a secret whose item became unreadable instead of clearing it", async () => {
      const c = await server.addItem({ folder: "obsidian", name: "k", value: "v" });
      await server.addItem({ folder: "obsidian", name: "other", value: "o" });
      await a.controller.sync();
      c.notes = "7.cose-payload"; // written by a newer client format
      const r = await a.controller.sync();
      expect(r.cleared).toEqual([]);
      expect(a.store.get("k")).toBe("v");
      expect(r.skipped.map((s) => s.reason)).toContainEqual(expect.stringMatching(/kept as is/));
      // Renamed to an invalid id or moved to an organization: also kept.
      c.notes = (await server.addItem({ folder: "tmp", name: "x", value: "v" })).notes;
      c.organizationId = "org";
      expect((await a.controller.sync()).cleared).toEqual([]);
    });

    it("never overwrites either side for a never-synced local value, whatever the policy", async () => {
      await server.addItem({ folder: "obsidian", name: "shared-id", value: "remote" });
      for (const policy of ["prefer-local", "prefer-remote"] as const) {
        const d = makeDevice(server.http, server.account, { settings: { conflictPolicy: policy } });
        await d.controller.unlock(server.account.password);
        d.store.set("shared-id", "someone else's");
        const r = await d.controller.sync();
        expect(r.conflicts.map((c) => c.kind)).toEqual(["local-unsynced"]);
        expect(d.store.get("shared-id")).toBe("someone else's");
      }
      expect(await remoteValue(server.ciphers[0]!.id)).toBe("remote");
    });

    it("ignores a conflict choice once the conflict changed kind", async () => {
      const c = await server.addItem({ folder: "obsidian", name: "k", value: "v1" });
      await server.addItem({ folder: "obsidian", name: "pad1", value: "p" });
      await server.addItem({ folder: "obsidian", name: "pad2", value: "p" });
      await a.controller.sync();
      a.store.set("k", "local");
      await server.editValue(c.id, "remote");
      expect((await a.controller.sync()).conflicts[0]!.kind).toBe("both-changed");
      c.deletedDate = server.nextRevision(); // now a deleted-remotely conflict
      const r = await a.controller.sync(new Map([["k", { policy: "prefer-remote", kind: "both-changed" }]]));
      expect(r.cleared).toEqual([]);
      expect(r.conflicts.map((x) => x.kind)).toEqual(["deleted-remotely"]);
      expect(a.store.get("k")).toBe("local");
    });

    it("keeps the scope when a deleted secret is uploaded again", async () => {
      a.store.set("dev", "x");
      a.store.set("pad", "y");
      a.controller.queueUpload("dev", { kind: "device", id: "" });
      a.controller.queueUpload("pad", { kind: "global" });
      await a.controller.sync();
      const item = server.ciphers[0]!;
      item.deletedDate = server.nextRevision();
      a.store.set("dev", "edited");
      await a.controller.sync(new Map([["dev", { policy: "prefer-local", kind: "deleted-remotely" }]]));
      const recreated = server.ciphers.at(-1)!;
      expect(recreated.id).not.toBe(item.id);
      const fields = await Promise.all(
        (recreated.fields ?? []).map(async (f) => [
          await decryptString(f.name!, server.account.userKey),
          await decryptString(f.value!, server.account.userKey),
        ]),
      );
      expect(fields).toContainEqual(["obsidian-scope", `device:${a.controller.deviceId()}`]);
    });

    it("does not overwrite a local edit made while the sync is running", async () => {
      const ca = await server.addItem({ folder: "obsidian", name: "a-first", value: "1" });
      const cb = await server.addItem({ folder: "obsidian", name: "b-second", value: "1" });
      await a.controller.sync();
      a.store.set("a-first", "pushed");
      await server.editValue(cb.id, "remote");
      server.beforeUpdate = (id) => {
        if (id === ca.id) a.store.set("b-second", "typed meanwhile");
      };
      const r = await a.controller.sync();
      expect(a.store.get("b-second")).toBe("typed meanwhile");
      expect(r.conflicts.map((x) => x.id)).toEqual(["b-second"]);
    });

    it("refuses to clear most secrets at once", async () => {
      const items = [];
      for (const n of ["k1", "k2", "k3", "k4"]) items.push(await server.addItem({ folder: "obsidian", name: n, value: "v" }));
      await a.controller.sync();
      for (const c of items.slice(0, 3)) c.deletedDate = server.nextRevision();
      await expect(a.controller.sync()).rejects.toThrow(/3 of 4 synced secrets would be cleared/);
      expect(a.store.get("k1")).toBe("v");
    });

    it("only sends the API key to the server it was entered for", async () => {
      const d = makeDevice(server.http, server.account);
      d.settings.serverUrl = "https://evil.example";
      server.requests = [];
      await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/saved for https:\/\/bw\.test/);
      expect(server.requests).toHaveLength(0);
      d.controller.setApiKey("clientSecret", server.account.clientSecret);
      expect(d.store.get("bitwarden-secrets-api-origin")).toBe("https://evil.example");
    });

    it("prefers the folder it synced from when several share the name", async () => {
      await server.addItem({ folder: "obsidian", name: "k", value: "v" });
      await a.controller.sync();
      const dup = await server.addFolder("obsidian");
      dup.id = "0000-sorts-first";
      expect((await a.controller.sync()).errors).toEqual([]);
      expect(a.store.get("k")).toBe("v");
    });

    it("stops a running sync when locked", async () => {
      for (let i = 0; i < 5; i++) await server.addItem({ folder: "obsidian", name: `k${i}`, value: "v" });
      const run = a.controller.sync();
      a.controller.lock();
      await expect(run).rejects.toThrow(/locked/);
      expect(a.controller.status).toBe("locked");
      expect(a.store.list().filter((id) => id.startsWith("k"))).toEqual([]);
    });

    it("refuses a remembered key it cannot verify", async () => {
      const d = makeDevice(server.http, server.account, { settings: { rememberKey: true } });
      await d.controller.unlock(server.account.password);
      d.controller.lock();
      (server as unknown as { privateKey: string | null }).privateKey = null;
      expect(await d.controller.unlockFromRememberedKey()).toBe(false);
      expect(d.store.get(SECRET_USER_KEY)).toBe("");
    });

    it("keeps unknown item properties when pushing", async () => {
      const c = await server.addItem({ folder: "obsidian", name: "k", value: "v" });
      (c as unknown as Record<string, unknown>).sshKey = { privateKey: "2.keep" };
      (c as unknown as Record<string, unknown>).archivedDate = "2026-01-02T00:00:00Z";
      await a.controller.sync();
      a.store.set("k", "w");
      await a.controller.sync();
      const after = server.ciphers.find((x) => x.id === c.id) as unknown as Record<string, unknown>;
      expect(after.sshKey).toEqual({ privateKey: "2.keep" });
      expect(after.archivedDate).toBe("2026-01-02T00:00:00Z");
    });
  });
});
