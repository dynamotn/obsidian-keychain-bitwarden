import { beforeEach, describe, expect, it } from "vitest";
import { argon2InThread, KdfAbortedError } from "../src/bw/argon2";
import { KdfType } from "../src/bw/crypto";
import type { HttpClient, HttpRequest } from "../src/bw/http";
import { SECRET_API_ORIGIN, SECRET_CLIENT_ID, SECRET_CLIENT_SECRET, SECRET_USER_KEY, type Status } from "../src/controller";
import { SyncAbortedError } from "../src/sync/engine";
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
      expect(await d.controller.unlockFromRememberedKey()).toBe(false);
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
      expect(d.store.get(SECRET_USER_KEY)).toBeNull();
    });

    it("is not used once remembering is turned off", async () => {
      const d = await remembering();
      d.settings.rememberKey = false;
      expect(await d.controller.unlockFromRememberedKey()).toBe(false);
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
    });

    it.each([
      ["not base64", "not base64!"],
      ["a key of the wrong size", btoa("short")],
    ])("is dropped when it is %s", async (_label, stored) => {
      const d = await remembering();
      d.store.set(SECRET_USER_KEY, stored);
      expect(await d.controller.unlockFromRememberedKey()).toBe(false);
      expect(d.store.get(SECRET_USER_KEY)).toBe("");
      expect(server.requests).toHaveLength(0);
      expect(d.controller.isUnlocked).toBe(false);
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
      await expect(first).rejects.toThrow(/500/);
      expect((await second).pulled).toEqual(["k"]);
      expect(d.controller.status).toBe("idle");
    });

    it("reports a lock during the last write as a cancellation, not as a result", async () => {
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      a.store.set("k", "w");
      server.beforeUpdate = () => a.controller.lock();
      await expect(a.controller.sync()).rejects.toBeInstanceOf(SyncAbortedError);
      expect(a.controller.status).toBe("locked");
    });
  });

  describe("uploads", () => {
    it("refuses a secret that does not exist on this device", () => {
      expect(() => a.controller.queueUpload("missing", { kind: "global" })).toThrow(/No local secret named "missing"/);
      expect(a.state().pendingCreates).toEqual([]);
    });

    it("queues a secret once, keeping the latest scope", () => {
      a.store.set("k", "v");
      a.controller.queueUpload("k", { kind: "global" });
      a.controller.queueUpload("k", { kind: "vault", name: "notes" });
      expect(a.state().pendingCreates).toEqual(["k"]);
      expect(a.state().pendingScopes).toEqual({ k: "vault:notes" });
    });
  });

  describe("resetState", () => {
    it("forgets the sync state but keeps the device id", async () => {
      await server.addItem({ name: "k", value: "v" });
      await a.controller.sync();
      const deviceId = a.controller.deviceId();
      a.controller.resetState();
      expect(a.state().base).toEqual({});
      expect(a.state().deviceId).toBe(deviceId);
    });

    it("refuses while a sync is running", async () => {
      await server.addItem({ name: "k", value: "v" });
      const run = a.controller.sync();
      expect(() => a.controller.resetState()).toThrow(/A sync is running/);
      await run;
      expect(Object.keys(a.state().base)).toEqual(["k"]);
    });
  });

  describe("notificationsHubUrl", () => {
    it("authenticates the hub with the current session", async () => {
      server.requests = [];
      await a.controller.sync();
      const token = server.requests.find(isVaultSync)!.headers!.Authorization!.replace(/^Bearer /, "");
      expect(await a.controller.notificationsHubUrl()).toBe(
        `wss://bw.test/notifications/hub?access_token=${encodeURIComponent(token)}`,
      );
    });

    it("fails while locked, without contacting the server", async () => {
      a.controller.lock();
      server.requests = [];
      await expect(a.controller.notificationsHubUrl()).rejects.toThrow("Bitwarden is locked");
      expect(server.requests).toHaveLength(0);
    });
  });
});
