import { beforeEach, describe, expect, it } from "vitest";
import { decryptString, KdfType, unwrapKey } from "../src/bw/crypto";
import { SECRET_USER_KEY } from "../src/controller";
import { ACCOUNT_KINDS, FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";
import type { CipherDto } from "../src/bw/api";
import { fromBase64, toBase64 } from "../src/bw/encoding";

/** Flips one ciphertext bit of an EncString, type 2 or 7. */
function tamper(enc: string): string {
  if (enc.startsWith("2.")) return enc.replace(/\|([A-Za-z0-9+/])/, (_m, ch: string) => `|${ch === "A" ? "B" : "A"}`);
  // Type 7: the COSE_Encrypt0 ends with the ciphertext and its tag.
  const bytes = fromBase64(enc.slice(2));
  bytes[bytes.length - 1]! ^= 1;
  return `7.${toBase64(bytes)}`;
}

describe.each(ACCOUNT_KINDS)("with a %s account key", (userKey) => {
  let server: FakeBitwardenServer;
  let a: TestDevice;
  let b: TestDevice;

  async function unlocked(device: TestDevice) {
    await device.controller.unlock(server.account.password);
    return device;
  }

  beforeEach(async () => {
    server = await FakeBitwardenServer.create(undefined, { userKey });
    a = await unlocked(makeDevice(server.http, server.account));
    b = await unlocked(makeDevice(server.http, server.account));
  });

  async function remoteValue(cipherId: string): Promise<string> {
    const c = server.ciphers.find((x) => x.id === cipherId)!;
    let key = server.account.userKey;
    if (c.key) key = await unwrapKey(c.key, key);
    // Where the plugin reads it from: an obsidian:password field, else the login password or the notes.
    for (const f of c.fields ?? []) {
      if ((await decryptString(f.name!, key)) === "obsidian:password") return f.value ? decryptString(f.value, key) : "";
    }
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
      await server.addItem({ name: "openai-api-key", value: "sk-1" });
      await server.addItem({ name: "Anthropic", id: "anthropic-key", value: "sk-ant", itemKey: true });
      await server.addItem({ name: "github-token", value: "ghp_x", type: 1 });
      await server.addItem({ folder: "elsewhere", name: "bank-pin", value: "1234", id: null });
      const report = await a.controller.sync();
      expect(report.pulled.sort()).toEqual(["anthropic-key", "github-token", "openai-api-key"]);
      expect(report.skipped).toEqual([]);
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
      await server.addItem({ name: "k", value: "v" });
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
      const login = await server.addItem({ name: "github-token", value: "old", type: 1 });
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
      const c = await server.addItem({ name: "k", value: "v1", itemKey: true });
      await a.controller.sync();
      a.store.set("k", "v2");
      await a.controller.sync();
      expect(await remoteValue(c.id)).toBe("v2");
      expect(server.ciphers.find((x) => x.id === c.id)!.key).toBe(c.key);
    });

    it("reports conflicts and resolves them per secret", async () => {
      const c = await server.addItem({ name: "k", value: "v1" });
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
      const c = await server.addItem({ name: "k", value: "v1" });
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
      const c = await server.addItem({ name: "k", value: "v" });
      await server.addItem({ name: "other", value: "o" });
      await a.controller.sync();
      server.ciphers.find((x) => x.id === c.id)!.deletedDate = server.nextRevision();
      expect((await a.controller.sync()).cleared).toEqual(["k"]);
      expect(a.store.get("k")).toBe("");
      expect(a.state().base.k).toBeUndefined();
    });

    it("refuses to wipe the device when every item disappears", async () => {
      await server.addItem({ name: "k1", value: "v" });
      await server.addItem({ name: "k2", value: "v" });
      await a.controller.sync();

      for (const c of server.ciphers) c.deletedDate = server.nextRevision();
      await expect(a.controller.sync()).rejects.toThrow(/refusing/);
      expect(a.store.get("k1")).toBe("v");
    });

    it("syncs marked items in any folder, or none, and ignores folders entirely", async () => {
      await server.addItem({ name: "no-folder", value: "1" });
      await server.addItem({ folder: "work", name: "in-work", value: "2" });
      await server.addItem({ name: "Not marked", value: "3", id: null });
      (await server.addItem({ name: "No fields", value: "4", id: null })).fields = null;
      expect((await a.controller.sync()).pulled.sort()).toEqual(["in-work", "no-folder"]);
      // Moving an item between folders changes nothing.
      server.ciphers[0]!.folderId = "work";
      server.ciphers[0]!.revisionDate = server.nextRevision();
      const r = await a.controller.sync();
      expect([...r.pulled, ...r.cleared, ...r.conflicts]).toEqual([]);
    });

    describe("blob-encrypted items", () => {
      const BLOB = JSON.stringify({ format_version: 1, wrapped_cek: "2.x", envelope: "y" });
      const blobify = (c: CipherDto) => {
        c.data = BLOB;
        c.name = "";
        c.notes = null;
        c.fields = null;
        c.login = null;
      };

      it("holds an item that was synced and then rewritten as a blob, instead of clearing it", async () => {
        const c = await server.addItem({ name: "k", value: "v" });
        await server.addItem({ name: "other", value: "o" });
        await a.controller.sync();
        blobify(c);
        c.revisionDate = server.nextRevision();
        const r = await a.controller.sync();
        expect(r.cleared).toEqual([]);
        expect(a.store.get("k")).toBe("v");
        expect(a.state().base.k).toBeDefined();
        expect(r.skipped.map((x) => x.cipherId)).toEqual([c.id]);
        expect(r.skipped[0]!.reason).toContain("kept as is");
        a.store.set("k", "w");
        const r2 = await a.controller.sync();
        expect([...r2.pushed, ...r2.created]).toEqual([]);
      });

      it("is not fooled by an Object.prototype.format_version set by another plugin", async () => {
        (await server.addItem({ name: "plain", value: "1" })).data = '{"Name":"x"}';
        Object.defineProperty(Object.prototype, "format_version", { value: 1, configurable: true, writable: true });
        try {
          expect((await a.controller.sync()).pulled).toEqual(["plain"]);
        } finally {
          delete (Object.prototype as Record<string, unknown>).format_version;
        }
      });

      it("neither adopts nor reports a new blob item", async () => {
        blobify(await server.addItem({ name: "fresh", value: "v" }));
        const r = await a.controller.sync();
        expect([...r.pulled, ...r.created, ...r.pushed, ...r.cleared, ...r.conflicts, ...r.skipped]).toEqual([]);
        expect(a.store.get("fresh")).toBeNull();
      });

      it("still reads a legacy item whose data is not a blob", async () => {
        (await server.addItem({ name: "plain", value: "1" })).data = JSON.stringify({ Name: "x", Notes: null, Fields: [] });
        (await server.addItem({ name: "obj", value: "2" })).data = '{"uris":[]}';
        (await server.addItem({ name: "arr", value: "3" })).data = "[1]";
        (await server.addItem({ name: "nul", value: "4" })).data = "null";
        (await server.addItem({ name: "txt", value: "5" })).data = "not json";
        expect((await a.controller.sync()).pulled.sort()).toEqual(["arr", "nul", "obj", "plain", "txt"]);
      });
    });

    it("stops syncing an item once its obsidian:id field is removed", async () => {
      const c = await server.addItem({ name: "k", value: "v" });
      await server.addItem({ name: "other", value: "o" });
      await a.controller.sync();
      c.fields = c.fields!.slice(1);
      c.revisionDate = server.nextRevision();
      expect((await a.controller.sync()).cleared).toEqual(["k"]);
    });

    it("reads and writes the value in an obsidian:password field when there is one", async () => {
      const login = await server.addItem({ name: "db", value: "from-field", defaultValue: "site-password", type: 1 });
      const note = await server.addItem({ name: "note", value: "note-field", defaultValue: "note text" });
      await a.controller.sync();
      expect(a.store.get("db")).toBe("from-field");
      expect(a.store.get("note")).toBe("note-field");

      a.store.set("db", "rotated");
      a.store.set("note", "edited");
      expect((await a.controller.sync()).pushed.sort()).toEqual(["db", "note"]);
      const key = server.account.userKey;
      const fieldValue = async (id: string) => {
        const c = server.ciphers.find((x) => x.id === id)!;
        for (const f of c.fields ?? []) {
          if ((await decryptString(f.name!, key)) === "obsidian:password") return decryptString(f.value!, key);
        }
        return null;
      };
      expect(await fieldValue(login.id)).toBe("rotated");
      expect(await fieldValue(note.id)).toBe("edited");
      const after = server.ciphers.find((x) => x.id === login.id)!;
      expect(after.login!.password).toBe(login.login!.password);
      expect(after.passwordHistory ?? null).toBeNull();
      expect(server.ciphers.find((x) => x.id === note.id)!.notes).toBe(note.notes);
      expect((await b.controller.sync()).pulled.sort()).toEqual(["db", "note"]);
      expect(b.store.get("db")).toBe("rotated");
    });

    it("skips items storing base64, which secret storage cannot hold", async () => {
      const binary = await server.addItem({ name: "cert", value: "AAEC", extraFields: [["obsidian:encoding", "base64"]] });
      // A base64 value claimed on the user's own login password (dybw ADR 0005) is never decoded.
      const login = await server.addItem({ name: "pw", value: "hunter2", type: 1, extraFields: [["obsidian:encoding", "base64"]] });
      const odd = await server.addItem({ name: "odd", value: "v", extraFields: [["obsidian:location", "attic"]] });
      await server.addItem({ name: "plain", value: "p" });
      const r = await a.controller.sync();
      expect(r.pulled).toEqual(["plain"]);
      for (const c of [binary, login]) {
        expect(r.skipped).toContainEqual({ cipherId: c.id, reason: '"obsidian:encoding" is not supported by this plugin' });
      }
      expect(r.skipped).toContainEqual({ cipherId: odd.id, reason: 'unknown "obsidian:location" value' });
      expect(a.store.get("cert")).toBeNull();
      expect(a.store.get("pw")).toBeNull();
    });

    describe("values too long for a field", () => {
      const long = "x".repeat(4_000); // over 5,000 encrypted characters
      const huge = "y".repeat(8_000); // over 10,000
      const fieldsOf = async (cipherId: string) => {
        const c = server.ciphers.find((x) => x.id === cipherId)!;
        const key = c.key ? await unwrapKey(c.key, server.account.userKey) : server.account.userKey;
        return Promise.all(
          (c.fields ?? []).map(async (f) => [await decryptString(f.name!, key), f.value ? await decryptString(f.value, key) : null]),
        );
      };

      it("upload into the notes of the new item, marked obsidian:location=notes, and sync back", async () => {
        a.store.set("pem", long);
        a.controller.queueUpload("pem", { kind: "global" });
        expect((await a.controller.sync()).created).toEqual(["pem"]);
        const c = server.ciphers[0]!;
        expect(await decryptString(c.notes!, server.account.userKey)).toBe(long);
        const fields = await fieldsOf(c.id);
        expect(fields).toContainEqual(["obsidian:location", "notes"]);
        expect(fields.map(([n]) => n)).not.toContain("obsidian:password");
        expect((await b.controller.sync()).pulled).toEqual(["pem"]);
        expect(b.store.get("pem")).toBe(long);

        // Shorter again: it stays where it is.
        b.store.set("pem", "short");
        await b.controller.sync();
        expect(await decryptString(server.ciphers[0]!.notes!, server.account.userKey)).toBe("short");
        expect((await a.controller.sync()).pulled).toEqual(["pem"]);
      });

      it("move out of an obsidian:password field into empty notes, dropping every copy of the field", async () => {
        const c = await server.addItem({
          name: "db",
          type: 1,
          value: "token",
          defaultValue: "site-password",
          extraFields: [["obsidian:password", "stale duplicate"]],
        });
        c.notes = null; // a login whose notes are empty
        await server.addItem({ name: "pad", value: "p" });
        await a.controller.sync();
        a.store.set("db", long);
        expect((await a.controller.sync()).pushed).toEqual(["db"]);
        const after = server.ciphers.find((x) => x.id === c.id)!;
        const key = server.account.userKey;
        expect(await decryptString(after.notes!, key)).toBe(long);
        expect(after.login!.password).toBe(c.login!.password);
        const fields = await fieldsOf(c.id);
        expect(fields.filter(([n]) => n === "obsidian:password")).toEqual([]);
        expect(fields).toContainEqual(["obsidian:location", "notes"]);
        expect(fields).toContainEqual(["unrelated", "keep me"]);
        expect((await b.controller.sync()).pulled.sort()).toEqual(["db", "pad"]);
        expect(b.store.get("db")).toBe(long);
      });

      it("fail without touching anything when the notes hold the user's text, or nothing fits", async () => {
        // A secure note with the user's own text and the secret in obsidian:password.
        const note = await server.addItem({ name: "note", value: "token", defaultValue: "my own notes" });
        const login = await server.addItem({ name: "site", type: 1, value: "pw" });
        const big = await server.addItem({ name: "big", value: "v", extraFields: [["obsidian:location", "notes"]] });
        await a.controller.sync();
        const before = structuredClone(server.ciphers);
        a.store.set("note", long);
        a.store.set("site", long);
        a.store.set("big", huge);
        const r = await a.controller.sync();
        expect(r.pushed).toEqual([]);
        expect(r.errors).toEqual([
          expect.stringMatching(/^big: the value is too long for the notes: [\d,]+ encrypted characters, at most 10,000 fit$/),
          expect.stringMatching(/^note: the value is too long for a field .*the notes hold your own text$/),
          expect.stringMatching(/^site: the value is too long for a login password/),
        ]);
        expect(r.errors.join()).not.toContain("xxxx");
        expect(server.ciphers).toEqual(before);
        expect(a.store.get("note")).toBe(long);
        for (const c of [note, login, big]) expect(server.ciphers.find((x) => x.id === c.id)!.revisionDate).toBe(c.revisionDate);
      });

      it.each([
        ["empty", ""],
        ["whitespace", "  \t"],
        ["without a value", null],
      ])("never overwrite the user's notes when obsidian:location is %s", async (_kind, location) => {
        const note = await server.addItem({
          name: "note",
          value: "token",
          defaultValue: "my own notes",
          extraFields: [["obsidian:location", location ?? ""]],
        });
        // Fields: obsidian:id, unrelated, obsidian:location, obsidian:password.
        if (location === null) note.fields![2]!.value = null;
        await a.controller.sync();
        expect(a.store.get("note")).toBe("token");
        const before = structuredClone(server.ciphers);
        a.store.set("note", long);
        const r = await a.controller.sync();
        expect(r.pushed).toEqual([]);
        expect(r.errors).toEqual([expect.stringMatching(/^note: the value is too long for a field .*the notes hold your own text$/)]);
        expect(server.ciphers).toEqual(before);
        expect(await decryptString(server.ciphers.find((x) => x.id === note.id)!.notes!, server.account.userKey)).toBe(
          "my own notes",
        );
      });

      it.each([
        ["empty", ""],
        ["whitespace", "  \t"],
      ])("keep a login's value in its own password when obsidian:location is %s", async (_kind, location) => {
        const login = await server.addItem({ name: "site", type: 1, value: "pw", extraFields: [["obsidian:location", location]] });
        await a.controller.sync();
        expect(a.store.get("site")).toBe("pw");
        a.store.set("site", "rotated");
        expect((await a.controller.sync()).pushed).toEqual(["site"]);
        expect(await remoteValue(login.id)).toBe("rotated");
        const after = server.ciphers.find((x) => x.id === login.id)!;
        expect(await decryptString(after.notes!, server.account.userKey)).toBe("login notes");
      });

      it("move into empty notes over an empty obsidian:location, setting it to notes", async () => {
        const c = await server.addItem({ name: "db", value: "token", defaultValue: "", extraFields: [["obsidian:location", ""]] });
        c.notes = null;
        await a.controller.sync();
        a.store.set("db", long);
        expect((await a.controller.sync()).pushed).toEqual(["db"]);
        const fields = await fieldsOf(c.id);
        expect(fields.filter(([n]) => n === "obsidian:location")).toEqual([["obsidian:location", "notes"]]);
        expect(fields.map(([n]) => n)).not.toContain("obsidian:password");
        expect(await decryptString(server.ciphers.find((x) => x.id === c.id)!.notes!, server.account.userKey)).toBe(long);
      });

      it("clear a stale copy in the notes when a value from obsidian:password fits again", async () => {
        // Another client left the old secret in the notes, marked as this tool's, next to an obsidian:password field.
        const c = await server.addItem({
          name: "db",
          value: "token",
          defaultValue: "old secret",
          extraFields: [["obsidian:location", "notes"]],
        });
        await a.controller.sync();
        expect(a.store.get("db")).toBe("token");
        a.store.set("db", "new token");
        expect((await a.controller.sync()).pushed).toEqual(["db"]);
        const after = server.ciphers.find((x) => x.id === c.id)!;
        expect(after.notes).toBeNull();
        const fields = await fieldsOf(c.id);
        expect(fields).toContainEqual(["obsidian:password", "new token"]);
        expect(fields.map(([n]) => n)).not.toContain("obsidian:location");
        expect(fields).toContainEqual(["unrelated", "keep me"]);
        expect((await b.controller.sync()).pulled).toEqual(["db"]);
        expect(b.store.get("db")).toBe("new token");
      });

      it("drop every obsidian:location with the stale notes, so a duplicate never takes over", async () => {
        const c = await server.addItem({
          name: "db",
          value: "token",
          defaultValue: "old secret",
          extraFields: [
            ["obsidian:location", "notes"],
            ["obsidian:location", "attic"],
          ],
        });
        await a.controller.sync();
        a.store.set("db", "new token");
        expect((await a.controller.sync()).pushed).toEqual(["db"]);
        expect(server.ciphers.find((x) => x.id === c.id)!.notes).toBeNull();
        expect((await fieldsOf(c.id)).map(([n]) => n)).not.toContain("obsidian:location");
        // Still a usable secret, not an item skipped for an unknown location.
        const r = await b.controller.sync();
        expect(r.skipped).toEqual([]);
        expect(b.store.get("db")).toBe("new token");
      });

      it("leave exactly one obsidian:location=notes when a value moves into the notes", async () => {
        const c = await server.addItem({
          name: "db",
          value: "token",
          defaultValue: "",
          extraFields: [
            ["obsidian:location", ""],
            ["obsidian:location", "attic"],
          ],
        });
        c.notes = null;
        await a.controller.sync();
        a.store.set("db", long);
        expect((await a.controller.sync()).pushed).toEqual(["db"]);
        const fields = await fieldsOf(c.id);
        expect(fields.filter(([n]) => n === "obsidian:location")).toEqual([["obsidian:location", "notes"]]);
        expect((await b.controller.sync()).pulled).toEqual(["db"]);
        expect(b.store.get("db")).toBe(long);
      });

      it("refuse an upload too long even for the notes, and keep it queued", async () => {
        a.store.set("huge", huge);
        a.controller.queueUpload("huge", { kind: "global" });
        const r = await a.controller.sync();
        expect(r.created).toEqual([]);
        expect(r.errors).toEqual([expect.stringMatching(/^huge: the value is too long for the notes/)]);
        expect(server.ciphers).toHaveLength(0);
        expect(a.state().pendingCreates).toEqual(["huge"]);
      });
    });

    it("files uploads in the configured folder, or in none", async () => {
      await server.addFolder("work");
      a.store.set("first", "1");
      a.controller.queueUpload("first", { kind: "global" });
      await a.controller.sync();
      const folder = server.folders.find((f) => f.id === server.ciphers[0]!.folderId)!;
      expect(await decryptString(folder.name, server.account.userKey)).toBe("obsidian");

      a.settings.uploadFolder = "";
      a.store.set("second", "2");
      a.controller.queueUpload("second", { kind: "global" });
      await a.controller.sync();
      expect(server.ciphers[1]!.folderId).toBeNull();
      expect(server.folders).toHaveLength(2);
    });

    it("respects vault and device scopes", async () => {
      await server.addItem({ name: "work", value: "w", scope: "vault:work" });
      await server.addItem({ name: "mine", value: "m", scope: `device:${a.controller.deviceId()}` });
      await server.addItem({ name: "bad-scope", value: "x", scope: "planet:mars" });
      const w = makeDevice(server.http, server.account, { vaultName: "work" });
      await w.controller.unlock(server.account.password);
      const rw = await w.controller.sync();
      expect(rw.pulled).toEqual(["work"]);
      expect(rw.skipped.map((s) => s.reason)).toContainEqual(expect.stringMatching(/obsidian:scope/));
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
      expect(scopes).toContainEqual(["obsidian:scope", `device:${a.controller.deviceId()}`]);
    });

    it("never lets Bitwarden overwrite the plugin's own credentials", async () => {
      const secret = await server.addItem({ name: "keychain-bitwarden-client-secret", value: "evil" });
      // One this device does not hold yet would otherwise be pulled without a conflict.
      const unused = await server.addItem({ name: "keychain-bitwarden-new-setting", value: "evil" });
      const legacy = await server.addItem({ name: "bitwarden-secrets-new-setting", value: "evil" });
      const r = await a.controller.sync();
      expect(r.pulled).toEqual([]);
      expect(r.conflicts).toEqual([]);
      expect(r.skipped.map((s) => s.cipherId).sort()).toEqual([secret.id, unused.id, legacy.id].sort());
      expect(r.skipped.map((s) => s.reason)).toContainEqual('id "keychain-bitwarden-new-setting" is reserved for the plugin');
      expect(a.store.get("keychain-bitwarden-client-secret")).toBe(server.account.clientSecret);
      expect(a.store.get("keychain-bitwarden-new-setting")).toBeNull();
      expect(a.store.get("bitwarden-secrets-new-setting")).toBeNull();
    });

    it("keeps credentials left under the pre-rename prefix out of sync and uploads", async () => {
      a.store.set("bitwarden-secrets-client-secret", "old-secret");
      await server.addItem({ name: "bitwarden-secrets-client-secret", value: "evil" });
      const r = await a.controller.sync();
      expect(r.pulled).toEqual([]);
      expect(a.store.get("bitwarden-secrets-client-secret")).toBe("old-secret");
      expect(a.controller.uploadCandidates()).not.toContain("bitwarden-secrets-client-secret");
      expect(() => a.controller.queueUpload("bitwarden-secrets-client-secret", { kind: "global" })).toThrow(/Cannot upload/);
    });

    it("skips undecryptable or invalid items without failing the sync", async () => {
      const bad = await server.addItem({ name: "tampered", value: "v" });
      bad.notes = tamper(bad.notes!);
      await server.addItem({ name: "Not A Valid Id", value: "v" });
      await server.addItem({ name: "good", value: "g" });
      const r = await a.controller.sync();
      expect(r.pulled).toEqual(["good"]);
      expect(r.skipped).toHaveLength(2);
    });

    it("uses the oldest of duplicate ids on every device, however they are edited", async () => {
      const first = await server.addItem({ name: "dup", value: "first" });
      const clone = await server.addItem({ name: "Dup", id: "dup", value: "clone" });
      const r = await a.controller.sync();
      expect(a.store.get("dup")).toBe("first");
      expect(r.skipped).toContainEqual({ cipherId: clone.id, reason: expect.stringMatching(/duplicate.*oldest/) });
      // Editing the clone makes it the newest revision; it still loses.
      await server.editValue(clone.id, "clone edited");
      await server.editValue(first.id, "first edited");
      await server.editValue(clone.id, "clone edited again");
      await a.controller.sync();
      expect(a.store.get("dup")).toBe("first edited");
      expect((await b.controller.sync()).pulled).toEqual(["dup"]);
      expect(b.store.get("dup")).toBe("first edited");
    });

    it("stores a new upload in an obsidian:password field, leaving the notes free", async () => {
      a.store.set("fresh", "s3cret");
      a.controller.queueUpload("fresh", { kind: "global" });
      await a.controller.sync();
      const c = server.ciphers[0]!;
      expect(c.type).toBe(2);
      expect(c.notes).toBeNull();
      expect(await remoteValue(c.id)).toBe("s3cret");
      // An edit goes back to that same field.
      a.store.set("fresh", "rotated");
      await a.controller.sync();
      expect(server.ciphers[0]!.notes).toBeNull();
      expect(await remoteValue(c.id)).toBe("rotated");
    });

    it("queues a call made during a running sync instead of dropping it", async () => {
      await server.addItem({ name: "k", value: "v" });
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
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      expect(Object.keys(a.state().base)).toEqual(["k"]);
      expect(Object.keys(b.state().base)).toEqual([]);
      expect(JSON.stringify(a.state())).not.toContain('"v"');
    });

    it("prefers a duplicate with a creation date, then the lowest item id", async () => {
      const undated = await server.addItem({ name: "dup", value: "undated" });
      undated.creationDate = null; // older servers send none
      await server.addItem({ name: "Dup", id: "dup", value: "dated" });
      // Same creation date: the lowest item id wins, wherever it is listed.
      const tie1 = await server.addItem({ name: "tie", value: "listed first" });
      const tie2 = await server.addItem({ name: "Tie", id: "tie", value: "lowest id" });
      tie2.creationDate = tie1.creationDate;
      tie1.id = "b-item";
      tie2.id = "a-item";
      const other1 = await server.addItem({ name: "other", value: "lowest id" });
      const other2 = await server.addItem({ name: "Other", id: "other", value: "listed last" });
      other2.creationDate = other1.creationDate;
      other1.id = "c-item";
      other2.id = "d-item";
      const r = await a.controller.sync();
      expect(a.store.get("dup")).toBe("dated");
      expect(a.store.get("tie")).toBe("lowest id");
      expect(a.store.get("other")).toBe("lowest id");
      expect(r.skipped.map((s) => s.cipherId).sort()).toEqual([undated.id, "b-item", "d-item"].sort());
    });

    it("skips marked items other than logins and secure notes", async () => {
      const card = await server.addItem({ name: "card", value: "v" });
      card.type = 3;
      const r = await a.controller.sync();
      expect(r.skipped).toEqual([{ cipherId: card.id, reason: "only login and secure note items are synced" }]);
      expect(a.store.get("card")).toBeNull();
    });

    it("reads a field or item part the server sends without a value as empty", async () => {
      const noId = await server.addItem({ name: "no-id", value: "v" });
      noId.fields![0]!.value = null; // the obsidian:id field
      const unnamed = await server.addItem({ name: "unnamed", value: "v" });
      unnamed.name = null as unknown as string;
      const r = await a.controller.sync();
      // An obsidian:id without a value is a blank marker: the item is unmarked (data model §2).
      expect(r.skipped).toEqual([]);
      expect(r.pulled).toEqual(["unnamed"]);
      a.store.set("unnamed", "local");
      await server.editValue(unnamed.id, "remote");
      expect((await a.controller.sync()).conflicts).toEqual([{ id: "unnamed", kind: "both-changed", label: "" }]);
    });

    it("pushes to items missing their login or secure note part", async () => {
      const login = await server.addItem({ name: "bare-login", type: 1, value: "x" });
      login.login = null;
      const note = await server.addItem({ name: "bare-note", value: "n" });
      note.secureNote = null;
      await a.controller.sync();
      expect(a.store.get("bare-login")).toBe("");
      a.store.set("bare-login", "pw");
      a.store.set("bare-note", "edited");
      expect((await a.controller.sync()).pushed).toEqual(["bare-login", "bare-note"]);
      expect(await remoteValue(login.id)).toBe("pw");
      expect(await remoteValue(note.id)).toBe("edited");
      expect(server.ciphers.find((c) => c.id === note.id)!.secureNote).toEqual({ type: 0 });
      expect((await b.controller.sync()).pulled).toEqual(["bare-login", "bare-note"]);
      expect(b.store.get("bare-login")).toBe("pw");
    });

    it("uploads and pushes an empty secret as no value", async () => {
      const login = await server.addItem({ name: "site", type: 1, value: "pw" });
      const note = await server.addItem({ name: "note", value: "token", defaultValue: "my own notes" });
      a.store.set("blank", "");
      a.controller.queueUpload("blank", { kind: "global" });
      expect((await a.controller.sync()).created).toEqual(["blank"]);
      a.store.set("site", "");
      a.store.set("note", "");
      expect((await a.controller.sync()).pushed).toEqual(["note", "site"]);
      const blank = server.ciphers.at(-1)!;
      const valueOf = async (cipherId: string) => {
        const c = server.ciphers.find((x) => x.id === cipherId)!;
        for (const f of c.fields ?? []) {
          if ((await decryptString(f.name!, server.account.userKey)) === "obsidian:password") return f.value;
        }
        return undefined;
      };
      expect(await valueOf(blank.id)).toBeNull();
      expect(blank.notes).toBeNull();
      expect(await valueOf(note.id)).toBeNull();
      expect(await decryptString(server.ciphers.find((x) => x.id === note.id)!.notes!, server.account.userKey)).toBe("my own notes");
      expect(server.ciphers.find((x) => x.id === login.id)!.login!.password).toBeNull();
      expect((await b.controller.sync()).pulled).toEqual(["blank", "note", "site"]);
      for (const id of ["blank", "note", "site"]) expect(b.store.get(id)).toBe("");
    });

    it("gives up after three passes when an item keeps changing under the push", async () => {
      const c = await server.addItem({ name: "k", value: "v1" });
      await a.controller.sync();
      a.store.set("k", "mine");
      server.beforeUpdate = (id) => {
        server.ciphers.find((x) => x.id === id)!.revisionDate = server.nextRevision();
      };
      const r = await a.controller.sync();
      expect(r.passes).toBe(3);
      expect(r.pushed).toEqual([]);
      expect(r.errors).toEqual(["Secrets kept changing during the sync; try again later."]);
      expect(await remoteValue(c.id)).toBe("v1");
      expect(a.store.get("k")).toBe("mine");
    });

    it("forgets a secret gone from both Bitwarden and this device, and a queued upload whose value is gone", async () => {
      const c = await server.addItem({ name: "k", value: "v" });
      await server.addItem({ name: "pad", value: "p" });
      await a.controller.sync();
      c.deletedDate = server.nextRevision();
      a.store.values.delete("k");
      a.store.set("queued", "x");
      a.controller.queueUpload("queued", { kind: "device", id: "" });
      a.store.values.delete("queued");
      const r = await a.controller.sync();
      expect([...r.pulled, ...r.created, ...r.cleared, ...r.conflicts, ...r.errors]).toEqual([]);
      expect(Object.keys(a.state().base)).toEqual(["pad"]);
      expect(a.state().pendingCreates).toEqual([]);
      expect(a.state().pendingScopes).toEqual({});
      expect(server.ciphers.filter((x) => !x.deletedDate)).toHaveLength(1);
    });

    it("uploads with the global scope when the queued scope is not one it knows", async () => {
      const d = makeDevice(server.http, server.account);
      d.localStorage.set("state", { version: 1, deviceId: "d1", base: {}, pendingCreates: ["k"], pendingScopes: { k: "planet:mars" } });
      d.store.set("k", "v");
      await unlocked(d);
      expect((await d.controller.sync()).created).toEqual(["k"]);
      const names = await Promise.all(server.ciphers[0]!.fields!.map((f) => decryptString(f.name!, server.account.userKey)));
      expect(names).not.toContain("obsidian:scope");
      expect(d.state().base.k!.scope).toBe("global");
      expect((await b.controller.sync()).pulled).toEqual(["k"]);
    });

    // Regression tests for the security review.
    describe("audit regressions", () => {
      it("keeps a secret whose item key can no longer be unwrapped instead of clearing it", async () => {
        const c = await server.addItem({ name: "k", value: "v", itemKey: true });
        await server.addItem({ name: "other", value: "o" });
        await a.controller.sync();
        c.key = tamper(c.key!);
        const r = await a.controller.sync();
        expect(r.cleared).toEqual([]);
        expect(a.store.get("k")).toBe("v");
        expect(a.state().base.k!.cipherId).toBe(c.id);
        expect(r.skipped).toEqual([{ cipherId: c.id, reason: '"k" is kept as is: its item can no longer be used' }]);
      });

      it("does not clear a secret edited while the sync is running", async () => {
        const first = await server.addItem({ name: "a-first", value: "1" });
        const gone = await server.addItem({ name: "b-gone", value: "1" });
        await a.controller.sync();
        a.store.set("a-first", "pushed");
        gone.deletedDate = server.nextRevision();
        server.beforeUpdate = (id) => {
          if (id === first.id) a.store.set("b-gone", "typed meanwhile");
        };
        const r = await a.controller.sync();
        expect(r.cleared).toEqual([]);
        expect(a.store.get("b-gone")).toBe("typed meanwhile");
        expect(r.conflicts.map((x) => [x.id, x.kind])).toEqual([["b-gone", "deleted-remotely"]]);
      });

      it("keeps a secret whose item became unreadable instead of clearing it", async () => {
        const c = await server.addItem({ name: "k", value: "v" });
        await server.addItem({ name: "other", value: "o" });
        await a.controller.sync();
        c.notes = "7.cose-payload"; // written by a newer client format
        const r = await a.controller.sync();
        expect(r.cleared).toEqual([]);
        expect(a.store.get("k")).toBe("v");
        expect(r.skipped.map((s) => s.reason)).toContainEqual(expect.stringMatching(/kept as is/));
        // Renamed to an invalid id or moved to an organization: also kept.
        c.notes = (await server.addItem({ name: "x", value: "v", id: null })).notes;
        c.organizationId = "org";
        expect((await a.controller.sync()).cleared).toEqual([]);
      });

      it("never overwrites either side for a never-synced local value, whatever the policy", async () => {
        await server.addItem({ name: "shared-id", value: "remote" });
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
        const c = await server.addItem({ name: "k", value: "v1" });
        await server.addItem({ name: "pad1", value: "p" });
        await server.addItem({ name: "pad2", value: "p" });
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
        expect(fields).toContainEqual(["obsidian:scope", `device:${a.controller.deviceId()}`]);
      });

      it("does not overwrite a local edit made while the sync is running", async () => {
        const ca = await server.addItem({ name: "a-first", value: "1" });
        const cb = await server.addItem({ name: "b-second", value: "1" });
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
        for (const n of ["k1", "k2", "k3", "k4"]) items.push(await server.addItem({ name: n, value: "v" }));
        await a.controller.sync();
        for (const c of items.slice(0, 3)) c.deletedDate = server.nextRevision();
        await expect(a.controller.sync()).rejects.toThrow(/3 of 4 synced secrets would be cleared/);
        expect(a.store.get("k1")).toBe("v");
      });

      it("refuses to clear exactly half of the secrets at once", async () => {
        const items = [];
        for (const n of ["k1", "k2", "k3", "k4"]) items.push(await server.addItem({ name: n, value: "v" }));
        await a.controller.sync();
        for (const c of items.slice(0, 2)) c.deletedDate = server.nextRevision();
        await expect(a.controller.sync()).rejects.toThrow(/2 of 4 synced secrets would be cleared/);
        expect(a.store.get("k1")).toBe("v");
      });

      it("still clears one secret deleted on its own", async () => {
        const items = [];
        for (const n of ["k1", "k2"]) items.push(await server.addItem({ name: n, value: "v" }));
        await a.controller.sync();
        items[0]!.deletedDate = server.nextRevision();
        expect((await a.controller.sync()).cleared).toEqual(["k1"]);
      });

      it("only sends the API key to the server it was entered for", async () => {
        const d = makeDevice(server.http, server.account);
        d.settings.serverUrl = "https://evil.example";
        server.requests = [];
        await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/saved for https:\/\/bw\.test/);
        expect(server.requests).toHaveLength(0);
        d.controller.setApiKey("clientSecret", server.account.clientSecret);
        expect(d.store.get("keychain-bitwarden-api-origin")).toBe("https://evil.example");
      });

      it("keeps the API key through a passing change of server, sending it only to its own", async () => {
        // The server URL is saved on every keystroke, and data.json may come from another device:
        // a refusal is enough, and deleting the key would turn a typo into a forced re-entry.
        const d = makeDevice(server.http, server.account);
        d.settings.serverUrl = "https://evil.example";
        server.requests = [];
        await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/saved for https:\/\/bw\.test/);
        expect(server.requests).toHaveLength(0);
        expect(d.store.get("keychain-bitwarden-client-secret")).toBe(server.account.clientSecret);
        expect(d.store.get("keychain-bitwarden-api-origin")).toBe("https://bw.test");
        d.settings.serverUrl = "https://bw.test";
        await d.controller.unlock(server.account.password);
        expect(d.controller.isUnlocked).toBe(true);
      });

      it("does not carry one part of the API key over to another server", async () => {
        const d = makeDevice(server.http, server.account);
        d.settings.serverUrl = "https://evil.example";
        d.controller.setApiKey("clientId", "attacker-chosen-id");
        expect(d.store.get("keychain-bitwarden-client-secret")).toBe("");
        server.requests = [];
        await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/API key/);
        expect(server.requests).toHaveLength(0);
        // Both parts entered for the same server keep each other.
        d.controller.setApiKey("clientSecret", "s");
        expect(d.store.get("keychain-bitwarden-client-id")).toBe("attacker-chosen-id");
      });

      it("files uploads in the same folder on every device when several share the name", async () => {
        await server.addFolder("obsidian");
        const dup = await server.addFolder("obsidian");
        dup.id = "0000-sorts-first";
        a.store.set("k", "v");
        a.controller.queueUpload("k", { kind: "global" });
        await a.controller.sync();
        expect(server.ciphers[0]!.folderId).toBe("0000-sorts-first");
      });

      it("stops a running sync when locked", async () => {
        for (let i = 0; i < 5; i++) await server.addItem({ name: `k${i}`, value: "v" });
        const run = a.controller.sync();
        a.controller.lock();
        await expect(run).rejects.toThrow(/locked/);
        expect(a.controller.status).toBe("locked");
        expect(a.store.list().filter((id) => /^k\d$/.test(id))).toEqual([]);
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
        const c = await server.addItem({ name: "k", value: "v" });
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
});
