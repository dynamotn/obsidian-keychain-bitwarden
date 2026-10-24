// The engine re-checks every action against what it read itself, so a planner
// bug can never write to the wrong item. These tests make the planner return
// actions it never should, and check that nothing is written.

import { beforeEach, describe, expect, it, vi } from "vitest";
import { BitwardenApi, resolveServerUrls } from "../src/bw/api";
import { decryptString, unwrapKey } from "../src/bw/crypto";
import { runSync, SyncAbortedError } from "../src/sync/engine";
import type { Action } from "../src/sync/plan";
import { newDeviceState } from "../src/sync/state";
import { FakeBitwardenServer, SERVER } from "./helpers/fakeServer";
import { makeDevice, MemorySecretStore, type TestDevice } from "./helpers/device";

const planner = vi.hoisted(() => ({ edit: null as ((actions: Action[]) => Action[]) | null }));
const keys = vi.hoisted(() => ({ withholdOrganization: false }));

vi.mock("../src/sync/plan", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/sync/plan")>();
  return {
    ...real,
    planSync: (input: Parameters<typeof real.planSync>[0]) => {
      const actions = real.planSync(input);
      return planner.edit ? planner.edit(actions) : actions;
    },
  };
});

// readVault keeps using the real lookup, so items are still read; only the
// engine's own lookup before a push can be made to come back empty.
vi.mock("../src/bw/vault", async (importOriginal) => {
  const real = await importOriginal<typeof import("../src/bw/vault")>();
  return {
    ...real,
    ownerKeyFor: (...args: Parameters<typeof real.ownerKeyFor>) =>
      keys.withholdOrganization && args[0].organizationId ? undefined : real.ownerKeyFor(...args),
  };
});

let server: FakeBitwardenServer;

beforeEach(async () => {
  planner.edit = null;
  keys.withholdOrganization = false;
  server = await FakeBitwardenServer.create();
});

async function remoteValue(cipherId: string): Promise<string> {
  const c = server.ciphers.find((x) => x.id === cipherId)!;
  let key = await server.ownerKey(c);
  if (c.key) key = await unwrapKey(c.key, key);
  return decryptString(c.notes!, key);
}

describe("runSync", () => {
  it("stops before the next item once cancelled, leaving it untouched", async () => {
    const first = await server.addItem({ name: "a-first", value: "1" });
    const second = await server.addItem({ name: "b-second", value: "1" });
    const api = new BitwardenApi(resolveServerUrls(SERVER), server.http, { identifier: "dev", name: "test" });
    await api.loginWithApiKey(server.account);
    const store = new MemorySecretStore();
    const state = newDeviceState();
    let cancelled = false;
    const run = () =>
      runSync({
        api,
        userKey: server.account.userKey,
        store,
        state,
        saveState: () => {},
        uploadFolder: "",
        vaultName: "notes",
        policy: "ask",
        isCancelled: () => cancelled,
      });
    expect((await run()).pulled).toEqual(["a-first", "b-second"]);

    store.set("a-first", "2");
    store.set("b-second", "2");
    // Locked while the first upload is on its way.
    server.beforeUpdate = () => {
      cancelled = true;
    };
    await expect(run()).rejects.toBeInstanceOf(SyncAbortedError);
    expect(await remoteValue(first.id)).toBe("2");
    expect(await remoteValue(second.id)).toBe("1");
    expect(state.base["b-second"]!.revisionDate).toBe(second.revisionDate);
  });
});

describe("the engine, given actions the planner should never return", () => {
  const org = { id: "" };
  let d: TestDevice;

  beforeEach(async () => {
    org.id = await server.addOrganization();
    d = makeDevice(server.http, server.account, { settings: { syncOrganizations: true } });
    await d.controller.unlock(server.account.password);
  });

  it("ignores a pull or push for an id it read no item for", async () => {
    await server.addItem({ name: "real", value: "v" });
    d.store.set("ghost", "local");
    planner.edit = (actions) => [...actions, { kind: "pull", id: "ghost" }, { kind: "push", id: "ghost" }];
    const r = await d.controller.sync();
    expect(r.pulled).toEqual(["real"]);
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(d.store.get("ghost")).toBe("local");
    expect(server.ciphers).toHaveLength(1);
  });

  it("never pushes for a secret this device does not hold", async () => {
    const c = await server.addItem({ name: "k", value: "remote" });
    await d.controller.sync();
    d.store.values.delete("k");
    // The planner restores it (a pull); a push read from the same missing value must do nothing.
    planner.edit = (actions) => [{ kind: "push", id: "k" }, ...actions];
    const r = await d.controller.sync();
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(await remoteValue(c.id)).toBe("remote");
    expect(server.ciphers.find((x) => x.id === c.id)!.revisionDate).toBe(c.revisionDate);
    expect(d.store.get("k")).toBe("remote");
  });

  it("refuses to push to an organization item the secret was not synced with, even confirmed", async () => {
    const personal = await server.addItem({ name: "api-key", value: "mine" });
    await server.addItem({ name: "pad", value: "p" });
    await d.controller.sync();
    personal.deletedDate = server.nextRevision();
    const planted = await server.addItem({ name: "api-key", value: "planted", organization: org.id });
    d.store.set("api-key", "edited");
    planner.edit = (actions) => actions.map((a) => (a.id === "api-key" ? { kind: "push", id: a.id, confirmed: true } : a));
    const r = await d.controller.sync();
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual(["api-key: refusing to upload to an organization item this secret was not synced with"]);
    expect(await remoteValue(planted.id)).toBe("planted");
    expect(d.state().base["api-key"]!.cipherId).toBe(personal.id);
  });

  it("refuses a confirmed push when the organization's key is not at hand", async () => {
    const c = await server.addItem({ name: "team-token", value: "theirs", organization: org.id });
    await d.controller.sync();
    d.store.set("team-token", "mine");
    keys.withholdOrganization = true;
    const r = await d.controller.sync(new Map([["team-token", { policy: "prefer-local", kind: "organization-push" }]]));
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual(["team-token: the key of its organization is not available"]);
    expect(await remoteValue(c.id)).toBe("theirs");
    expect(d.state().base["team-token"]!.pushConfirmed).toBeUndefined();
  });

  it("refuses the first push to an organization item without the user's confirmation", async () => {
    const c = await server.addItem({ name: "team-token", value: "theirs", organization: org.id });
    await d.controller.sync();
    d.store.set("team-token", "mine");
    planner.edit = (actions) => actions.map((a) => (a.id === "team-token" ? { kind: "push", id: a.id } : a));
    const r = await d.controller.sync();
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual(["team-token: refusing to upload to an organization item without your confirmation"]);
    expect(await remoteValue(c.id)).toBe("theirs");
    expect(d.state().base["team-token"]!.pushConfirmed).toBeUndefined();
  });
});
