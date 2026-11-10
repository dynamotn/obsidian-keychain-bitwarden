import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WasmSession } from "../vendor/dybw-core/dybw_core_wasm.js";
import { argon2InThread, KdfAbortedError } from "../src/bw/argon2";
import {
  needsNotice,
  SECRET_API_ORIGIN,
  SECRET_CLIENT_SECRET,
  SECRET_USER_KEY,
  TRAP_MESSAGE,
  type Status,
} from "../src/controller";
import { ApiError, LockedError, OriginNotAcknowledgedError, PortError, WrongPasswordError } from "../src/core/errors";
import { STORAGE_PREFIX, type SocketLike } from "../src/core/ports";
import { KdfType } from "./helpers/bw/crypto";
import type { HttpClient, HttpRequest } from "./helpers/bw/http";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";

// Controller behaviour not tied to the account's key type; the end-to-end sync
// behaviour, for every key type, is in sync.test.ts.

const isPrelogin = (r: HttpRequest) => r.url.endsWith("/identity/accounts/prelogin");
const isVaultSync = (r: HttpRequest) => r.url.includes("/api/sync");

describe("SecretsController", () => {
  let server: FakeBitwardenServer;
  let a: TestDevice;

  beforeEach(async () => {
    server = await FakeBitwardenServer.create();
    a = makeDevice(server.http, server.account);
    await a.controller.unlock(server.account.password);
  });

  afterEach(() => vi.restoreAllMocks());

  describe("status", () => {
    it("reports every change to listeners until they unsubscribe", async () => {
      const seen: [Status, string | undefined][] = [];
      const off = a.controller.onStatus((s, detail) => seen.push([s, detail]));
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      a.store.set("k", "local");
      await server.editValue(server.ciphers[0]!.id, "remote");
      await a.controller.sync();
      off();
      a.controller.lock();
      expect(seen).toEqual([
        ["syncing", undefined],
        ["idle", undefined],
        ["syncing", undefined],
        ["conflict", "1 conflict(s)"],
      ]);
      expect(a.controller.status).toBe("locked");
    });

    it("reports the sync's errors, one per line", async () => {
      await server.addItem({ name: "big", value: "v", extraFields: [["obsidian:location", "notes"]] });
      await a.controller.sync();
      a.store.set("big", "y".repeat(8_000));
      const r = await a.controller.sync();
      expect(r.errors).toHaveLength(1);
      expect(a.controller.status).toBe("error");
    });
  });

  describe("unlock", () => {
    it("needs the account email before contacting the server", async () => {
      const d = makeDevice(server.http, server.account, { settings: { email: "  " } });
      server.requests = [];
      await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/account email/);
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
    });

    it("stops before deriving the key when cancelled", async () => {
      const d = makeDevice(server.http, server.account);
      server.requests = [];
      const run = d.controller.unlock(server.account.password);
      d.controller.cancelUnlock();
      await expect(run).rejects.toBeInstanceOf(KdfAbortedError);
      // The KDF parameters are fetched first thing in the derivation.
      expect(server.requests.filter(isPrelogin)).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
    });

    it("lets a lock that arrives while the key is derived win", async () => {
      server = await FakeBitwardenServer.create({ type: KdfType.Argon2id, iterations: 2, memory: 16, parallelism: 1 });
      // A runner that cannot be interrupted: the derivation completes anyway.
      const d: TestDevice = makeDevice(server.http, server.account, {
        settings: { rememberKey: true },
        argon2: (input) => {
          d.controller.lock();
          return argon2InThread(input);
        },
      });
      await expect(d.controller.unlock(server.account.password)).rejects.toBeInstanceOf(KdfAbortedError);
      expect(d.controller.isUnlocked).toBe(false);
      expect(d.controller.status).toBe("locked");
      expect(d.store.get(SECRET_USER_KEY)).toBeNull();
    });

    it("lets a lock that arrives just after the core unlocked win", async () => {
      const d = makeDevice(server.http, server.account);
      const unlock = WasmSession.prototype.unlock;
      vi.spyOn(WasmSession.prototype, "unlock").mockImplementation(async function (this: WasmSession, ...args) {
        const summary = await unlock.apply(this, args);
        d.controller.lock();
        return summary;
      });
      await expect(d.controller.unlock(server.account.password)).rejects.toBeInstanceOf(KdfAbortedError);
      expect(d.controller.isUnlocked).toBe(false);
      vi.restoreAllMocks();
      await expect(d.controller.sync()).rejects.toBeInstanceOf(LockedError);
    });

    it("is locked after a failed unlock while unlocked: the core locked first, so the unlock is offered", async () => {
      const seen: Status[] = [];
      a.controller.onStatus((s) => seen.push(s));
      await expect(a.controller.unlock("wrong")).rejects.toBeInstanceOf(WrongPasswordError);
      expect(a.controller.isUnlocked).toBe(false);
      expect(a.controller.status).toBe("locked");
      expect(seen).toEqual(["locked"]);
      await expect(a.controller.sync()).rejects.toBeInstanceOf(LockedError);
    });

    it("needs a self-hosted server acknowledged on this device first, and sends it nothing before (ADR 0018)", async () => {
      const d = makeDevice(server.http, server.account);
      d.localStorage.delete(`${STORAGE_PREFIX}acknowledged-origins`);
      server.requests = [];
      const error = await d.controller.unlock(server.account.password).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(OriginNotAcknowledgedError);
      expect((error as OriginNotAcknowledgedError).origin).toBe("https://bw.test");
      expect(server.requests.filter((r) => r.url.endsWith("/connect/token"))).toHaveLength(0);
    });

    it("answers the unlock summary, with the organizations it could not read", async () => {
      const broken = await server.addOrganization({ key: "4.AAAA" });
      const d = makeDevice(server.http, server.account, { settings: { syncOrganizations: true } });
      const summary = await d.controller.unlock(server.account.password);
      expect(summary).toMatchObject({ securityVersion: 0, warnings: [expect.stringMatching(/below the recommended floor/)] });
      expect(summary.orgProblems.map((p) => p.organization)).toEqual([broken]);
    });
  });

  describe("organizations setting", () => {
    it("locks when it changes: the organizations to sync go into the profile at unlock", async () => {
      a.controller.organizationsChanged();
      expect(a.controller.isUnlocked).toBe(false);
      expect(a.controller.status).toBe("locked");
      await expect(a.controller.sync()).rejects.toBeInstanceOf(LockedError);
    });
  });

  describe("API key", () => {
    it("refuses a key that was never bound to a server, without sending it", async () => {
      // As left by a version that did not record the server the key was entered for.
      const d = makeDevice(server.http, server.account);
      d.store.values.delete(SECRET_API_ORIGIN);
      server.requests = [];
      await expect(d.controller.unlock(server.account.password)).rejects.toThrow(
        /saved for another server, not https:\/\/bw\.test/,
      );
      expect(server.requests).toHaveLength(0);
      // Left in place: only entering the key again binds it, which also clears the other part.
      expect(d.store.get(SECRET_CLIENT_SECRET)).toBe(server.account.clientSecret);
      expect(d.store.get(SECRET_API_ORIGIN)).toBeNull();
    });

    it("needs both parts before contacting the server", async () => {
      const d = makeDevice(server.http, server.account);
      d.store.set(SECRET_CLIENT_SECRET, " ");
      server.requests = [];
      await expect(d.controller.unlock(server.account.password)).rejects.toThrow(/Set the Bitwarden API key/);
      expect(server.requests).toHaveLength(0);
    });

    it.each([
      ["https://vault.bitwarden.com", "https://identity.bitwarden.com"],
      ["https://bitwarden.eu/", "https://identity.bitwarden.eu"],
      ["", "https://identity.bitwarden.com"],
      ["https://bw.example:8443/vault", "https://bw.example:8443"],
    ])("binds a key entered for %j to %s", (serverUrl, origin) => {
      a.settings.serverUrl = serverUrl;
      a.controller.setApiKey("clientId", "id");
      expect(a.store.get(SECRET_API_ORIGIN)).toBe(origin);
    });

    it("refuses a server URL it cannot read", () => {
      a.settings.serverUrl = "not a url";
      expect(() => a.controller.setApiKey("clientId", "id")).toThrow("Invalid server URL: not a url");
    });
  });

  describe("remembered key", () => {
    async function remembering(): Promise<TestDevice> {
      const d = makeDevice(server.http, server.account, { settings: { rememberKey: true } });
      await d.controller.unlock(server.account.password);
      d.controller.lock();
      server.requests = [];
      return d;
    }

    it("is not used when there is none", async () => {
      const d = makeDevice(server.http, server.account, { settings: { rememberKey: true } });
      server.requests = [];
      expect(await d.controller.unlockFromRememberedKey()).toBeNull();
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
      expect(d.store.get(SECRET_USER_KEY)).toBeNull();
    });

    it("is not used once remembering is turned off", async () => {
      const d = await remembering();
      d.settings.rememberKey = false;
      expect(await d.controller.unlockFromRememberedKey()).toBeNull();
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
    });

    it.each([
      ["not base64", "not base64!"],
      ["a key of the wrong size", btoa("short")],
    ])("is dropped when it is %s", async (_label, stored) => {
      const d = await remembering();
      d.store.set(SECRET_USER_KEY, stored);
      expect(await d.controller.unlockFromRememberedKey()).toBeNull();
      expect(d.store.get(SECRET_USER_KEY)).toBe("");
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
    });

    it("answers the unlock summary, with the organizations it could not read", async () => {
      const broken = await server.addOrganization({ key: "4.AAAA" });
      const d = await remembering();
      d.settings.syncOrganizations = true;
      const summary = await d.controller.unlockFromRememberedKey();
      expect(summary?.orgProblems.map((p) => p.organization)).toEqual([broken]);
      expect(d.controller.isUnlocked).toBe(true);
    });

    it("is kept when the server cannot be reached, for the next try", async () => {
      const d = await remembering();
      const key = d.store.get(SECRET_USER_KEY);
      d.localStorage.delete(`${STORAGE_PREFIX}acknowledged-origins`);
      await expect(d.controller.unlockFromRememberedKey()).rejects.toBeInstanceOf(OriginNotAcknowledgedError);
      expect(d.store.get(SECRET_USER_KEY)).toBe(key);
    });
  });

  describe("sync", () => {
    it("refuses to run while locked", async () => {
      a.controller.lock();
      server.requests = [];
      await expect(a.controller.sync()).rejects.toThrow("Bitwarden is locked");
      expect(server.requests).toHaveLength(0);
    });

    it("merges the conflict choices of every call queued behind a running sync", async () => {
      for (const name of ["k1", "k2"]) await server.addItem({ name, value: "v" });
      await a.controller.sync();
      for (const [i, c] of server.ciphers.entries()) {
        a.store.set(`k${i + 1}`, "local");
        await server.editValue(c.id, "remote");
      }
      const first = a.controller.sync();
      const second = a.controller.sync(new Map([["k1", { policy: "prefer-remote", kind: "both-changed" }]]));
      const third = a.controller.sync(new Map([["k2", { policy: "prefer-remote", kind: "both-changed" }]]));
      const [r1, r2, r3] = await Promise.all([first, second, third]);
      expect(r1.conflicts.map((c) => c.id).sort()).toEqual(["k1", "k2"]);
      expect(r3).toBe(r2);
      expect(r2.pulled.sort()).toEqual(["k1", "k2"]);
      expect(a.store.get("k1")).toBe("remote");
      expect(a.store.get("k2")).toBe("remote");
    });

    it("merges the history answers of every call queued behind a running sync", async () => {
      const login = await server.addItem({ name: "site", type: 1, value: "pw" });
      await a.controller.sync();
      a.store.set("site", "rotated");
      const first = a.controller.sync();
      const second = a.controller.sync(undefined, new Map([["site", { question: "first-write-back", answer: "write-to-login" }]]));
      const third = a.controller.sync();
      const [r1, r2, r3] = await Promise.all([first, second, third]);
      expect(r1.questions).toEqual([{ id: "site", label: "site", question: "first-write-back" }]);
      expect(r1.pushed).toEqual([]);
      expect(r3).toBe(r2);
      expect(r2.pushed).toEqual(["site"]);
      expect(server.ciphers.find((c) => c.id === login.id)!.revisionDate).not.toBe(login.revisionDate);
    });

    it("accepts the server's versions in a sync queued behind a running one", async () => {
      const c = await server.addItem({ name: "k", value: "old" });
      const old = c.revisionDate;
      await a.controller.sync();
      await server.editValue(c.id, "new");
      await a.controller.sync();
      await server.editValue(c.id, "old");
      c.revisionDate = old;
      const first = a.controller.sync();
      const second = a.controller.sync(undefined, undefined, true);
      const [r1, r2] = await Promise.all([first, second]);
      expect(r1.rollbacks).toHaveLength(1);
      expect(r2.rollbacks).toEqual([]);
      expect(a.store.get("k")).toBe("old");
    });

    it("syncs once more after a value typed during the sync, and only once", async () => {
      const first = await server.addItem({ name: "a-first", value: "1" });
      const second = await server.addItem({ name: "b-second", value: "1" });
      a.settings.conflictPolicy = "prefer-remote";
      await a.controller.sync();
      const base = a.state().base["b-second"];
      a.store.set("a-first", "pushed");
      await server.editValue(second.id, "remote");
      // On every push the user types again: into the secret being pushed, and into the one being pulled.
      let typed = 0;
      server.beforeUpdate = (id) => {
        // Bounded here only so that a controller retrying without end fails this test instead of hanging it.
        if (id !== first.id || typed === 3) return;
        typed++;
        a.store.set("a-first", `pushed ${typed}`);
        a.store.set("b-second", `typed ${typed}`);
      };
      const runSync = vi.spyOn(WasmSession.prototype, "runSync");
      await expect(a.controller.sync()).rejects.toBeInstanceOf(PortError);
      expect(runSync).toHaveBeenCalledTimes(2);
      expect(a.store.get("b-second")).toBe("typed 2");
      expect(a.state().base["b-second"]).toEqual(base);
    });

    it("never writes over a secret created during the sync with the id of one it pulls", async () => {
      const first = await server.addItem({ name: "a-first", value: "1" });
      await a.controller.sync();
      await server.addItem({ name: "fresh", value: "remote" });
      a.store.set("a-first", "pushed");
      server.beforeUpdate = (id) => {
        if (id === first.id) a.store.set("fresh", "mine");
      };
      const r = await a.controller.sync();
      expect(a.store.get("fresh")).toBe("mine");
      expect(r.conflicts.map((c) => [c.id, c.kind])).toEqual([["fresh", "local-unsynced"]]);
    });

    it("still runs a queued sync when the running one fails", async () => {
      let failNextSync = false;
      const http: HttpClient = async (req) => {
        if (failNextSync && isVaultSync(req)) {
          failNextSync = false;
          return { status: 500, text: JSON.stringify({ message: "boom" }) };
        }
        return server.http(req);
      };
      const d = makeDevice(http, server.account);
      await d.controller.unlock(server.account.password);
      await server.addItem({ name: "k", value: "v" });
      failNextSync = true;
      const first = d.controller.sync();
      const second = d.controller.sync();
      const error = await first.catch((e: unknown) => e);
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).status).toBe(500);
      expect((await second).pulled).toEqual(["k"]);
      expect(d.controller.status).toBe("idle");
    });

    it("reports a lock during the last write as a cancellation, not as a result", async () => {
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      a.store.set("k", "w");
      server.beforeUpdate = () => a.controller.lock();
      await expect(a.controller.sync()).rejects.toBeInstanceOf(LockedError);
      expect(a.controller.status).toBe("locked");
    });
  });

  describe("uploads", () => {
    it("refuses a secret that does not exist on this device", async () => {
      await expect(a.controller.queueUpload("missing", { kind: "global" })).rejects.toThrow(/No local secret named "missing"/);
      expect(a.state().pendingCreates).toEqual([]);
    });

    it("queues a secret once, keeping the latest scope", async () => {
      a.store.set("k", "v");
      await a.controller.queueUpload("k", { kind: "global" });
      await a.controller.queueUpload("k", { kind: "vault", name: "notes" });
      expect(a.state().pendingCreates).toEqual(["k"]);
      expect(a.state().pendingScopes).toEqual({ k: "vault:notes" });
    });

    it("lists the local secrets neither synced nor queued", async () => {
      await server.addItem({ name: "synced", value: "v" });
      await a.controller.sync();
      for (const id of ["queued", "zeta", "alpha"]) a.store.set(id, "x");
      await a.controller.queueUpload("queued", { kind: "global" });
      expect(await a.controller.uploadCandidates()).toEqual(["alpha", "zeta"]);
    });
  });

  describe("resetState", () => {
    it("forgets the sync state but keeps the device id", async () => {
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      const deviceId = await a.controller.deviceId();
      await a.controller.resetState();
      expect(a.state().base).toEqual({});
      expect(a.state().deviceId).toBe(deviceId);
    });

    it("waits for a running sync, then resets", async () => {
      await server.addItem({ name: "k", value: "v" });
      const run = a.controller.sync();
      const reset = a.controller.resetState();
      expect((await run).pulled).toEqual(["k"]);
      await reset;
      expect(a.state().base).toEqual({});
    });
  });

  describe("notifications hub", () => {
    /** A socket that records where it was opened, then fails: the hub backs off until stopped. */
    function recordingSocket(urls: string[]) {
      return (url: string): SocketLike => {
        urls.push(url);
        throw new Error("offline");
      };
    }

    it("authenticates the hub with the current session", async () => {
      const urls: string[] = [];
      const d = makeDevice(server.http, server.account, { createSocket: recordingSocket(urls) });
      await d.controller.unlock(server.account.password);
      server.requests = [];
      await d.controller.sync();
      const token = server.requests.find(isVaultSync)!.headers!.Authorization!.replace(/^Bearer /, "");
      const hub = d.controller.startHub(() => undefined);
      expect(d.controller.startHub(() => undefined)).not.toBe(hub);
      await vi.waitFor(() => expect(urls).toHaveLength(1));
      expect(urls[0]).toBe(`wss://bw.test/notifications/hub?access_token=${encodeURIComponent(token)}`);
      d.controller.stopHub();
      await hub;
    });

    it("fails while locked, without contacting the server", async () => {
      const urls: string[] = [];
      const d = makeDevice(server.http, server.account, { createSocket: recordingSocket(urls) });
      server.requests = [];
      await d.controller.startHub(() => undefined);
      expect(urls).toEqual([]);
      expect(server.requests).toHaveLength(0);
    });

    it("ends quietly when the core refuses it", async () => {
      vi.spyOn(WasmSession.prototype, "runHub").mockRejectedValue(JSON.stringify({ code: "locked", message: "Bitwarden is locked" }));
      await expect(a.controller.startHub(() => undefined)).resolves.toBeUndefined();
    });

    it("stops when locked", async () => {
      const urls: string[] = [];
      const d = makeDevice(server.http, server.account, { createSocket: recordingSocket(urls) });
      await d.controller.unlock(server.account.password);
      const hub = d.controller.startHub(() => undefined);
      await vi.waitFor(() => expect(urls).toHaveLength(1));
      d.controller.lock();
      await hub;
    });
  });

  describe("a trap in the core", () => {
    it("a_trap_locks_and_asks_to_reload", async () => {
      const notices: string[] = [];
      const d = makeDevice(server.http, server.account, { onTrap: (m) => notices.push(m) });
      await d.controller.unlock(server.account.password);
      const lock = vi.spyOn(WasmSession.prototype, "lock").mockImplementation(() => {
        throw new WebAssembly.RuntimeError("unreachable");
      });
      vi.spyOn(WasmSession.prototype, "runSync").mockRejectedValue(new WebAssembly.RuntimeError("unreachable"));
      await expect(d.controller.sync()).rejects.toThrow(TRAP_MESSAGE);
      expect(lock).toHaveBeenCalledTimes(1);
      expect(notices).toEqual([TRAP_MESSAGE]);
      expect(d.controller.isUnlocked).toBe(false);
      expect(d.controller.status).toBe("error");
      // Only a reload recovers: every later call is refused, once told.
      vi.restoreAllMocks();
      server.requests = [];
      await expect(d.controller.unlock(server.account.password)).rejects.toThrow(TRAP_MESSAGE);
      await expect(d.controller.deviceId()).rejects.toThrow(TRAP_MESSAGE);
      d.controller.trap();
      expect(notices).toHaveLength(1);
      expect(server.requests).toHaveLength(0);
    });

    it("never calls the trapped instance again, and refuses queued work instead of waiting", async () => {
      const d = makeDevice(server.http, server.account);
      await d.controller.unlock(server.account.password);
      // A trap inside a polled future: its promise never settles, the plugin hears of it from the window.
      vi.spyOn(WasmSession.prototype, "runSync").mockReturnValue(new Promise<string>(() => undefined));
      const stuck = d.controller.sync();
      const queued = d.controller.sync();
      d.controller.trap();
      const lock = vi.spyOn(WasmSession.prototype, "lock");
      await expect(d.controller.sync()).rejects.toThrow(TRAP_MESSAGE);
      await expect(d.controller.resetState()).rejects.toThrow(TRAP_MESSAGE);
      await expect(d.controller.uploadCandidates()).rejects.toThrow(TRAP_MESSAGE);
      d.controller.cancelUnlock();
      d.controller.lock();
      expect(lock).not.toHaveBeenCalled();
      // The reload notice stays what the status says.
      expect(d.controller.status).toBe("error");
      void stuck.catch(() => undefined);
      void queued.catch(() => undefined);
    });

    it("is also caught from a synchronous call", async () => {
      const d = makeDevice(server.http, server.account);
      await d.controller.unlock(server.account.password);
      vi.spyOn(WasmSession.prototype, "syncedIds").mockImplementation(() => {
        throw new WebAssembly.RuntimeError("unreachable");
      });
      await expect(d.controller.uploadCandidates()).rejects.toThrow(TRAP_MESSAGE);
      expect(d.controller.isUnlocked).toBe(false);
    });
  });

  describe("needsNotice", () => {
    const empty = { pulled: [], pushed: [], created: [], cleared: [], conflicts: [], errors: [], warnings: [] };
    it.each([
      ["nothing happened", {}, false],
      ["a pull", { pulled: ["k"] }, true],
      ["a conflict", { conflicts: [{ id: "k", kind: "both-changed", label: "k" }] }, true],
      ["an error", { errors: [{ id: "k", error: "e" }] }, true],
      ["only a warning", { warnings: ["1 secrets kept changing during the sync: sync again later"] }, true],
    ])("a background sync with %s", (_kind, part, expected) => {
      expect(needsNotice({ ...empty, ...part } as unknown as Parameters<typeof needsNotice>[0])).toBe(expected);
    });
  });
});
