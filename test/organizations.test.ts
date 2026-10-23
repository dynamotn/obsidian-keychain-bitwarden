import { beforeEach, describe, expect, it } from "vitest";
import { AccountPrivateKey, CryptoError, decryptBytes, decryptString, encryptBytes, SymmetricKey } from "../src/bw/crypto";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";

let server: FakeBitwardenServer;
let org: string;
let a: TestDevice;

async function device(syncOrganizations = true): Promise<TestDevice> {
  const d = makeDevice(server.http, server.account, { settings: { syncOrganizations } });
  await d.controller.unlock(server.account.password);
  return d;
}

/** Decrypts an item's secret value the way another member of its organization would. */
async function remoteValue(cipherId: string): Promise<string> {
  const c = server.ciphers.find((x) => x.id === cipherId)!;
  let key = await server.ownerKey(c);
  if (c.key) key = await SymmetricKey.fromBytes(await decryptBytes(c.key, key));
  return decryptString((c.type === 1 ? (c.login!.password as string) : c.notes)!, key);
}

beforeEach(async () => {
  server = await FakeBitwardenServer.create();
  org = await server.addOrganization();
  a = await device();
});

describe("organization items", () => {
  it("are left alone unless enabled", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "team-token", value: "t", organization: org });
    const off = await device(false);
    const r = await off.controller.sync();
    expect(r.pulled).toEqual([]);
    expect(off.store.get("team-token")).toBeNull();
    expect(r.skipped).toContainEqual({ cipherId: c.id, reason: expect.stringMatching(/enabled in the settings/) });
  });

  it("are pulled with the organization's key", async () => {
    await server.addItem({ folder: "obsidian", name: "team-token", value: "t0k3n", organization: org });
    await server.addItem({ folder: "obsidian", name: "team-login", value: "pw", type: 1, organization: org });
    await server.addItem({ folder: "obsidian", name: "team-keyed", value: "k", organization: org, itemKey: true });
    const r = await a.controller.sync();
    expect(r.pulled.sort()).toEqual(["team-keyed", "team-login", "team-token"]);
    expect(a.store.get("team-token")).toBe("t0k3n");
    expect(a.store.get("team-login")).toBe("pw");
    expect(a.store.get("team-keyed")).toBe("k");
  });

  it("accept organization keys wrapped with RSA-OAEP SHA-256 too", async () => {
    const org256 = await server.addOrganization({ keyType: 3 });
    await server.addItem({ folder: "obsidian", name: "sha256", value: "v", organization: org256 });
    expect((await a.controller.sync()).pulled).toEqual(["sha256"]);
  });

  it("are pushed back encrypted for the organization, which keeps the item", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "team-token", value: "old", organization: org, itemKey: true });
    await a.controller.sync();
    a.store.set("team-token", "new");
    const r = await a.controller.sync();
    expect(r.pushed).toEqual(["team-token"]);
    const after = server.ciphers.find((x) => x.id === c.id)!;
    expect(after.organizationId).toBe(org);
    expect(await remoteValue(c.id)).toBe("new");
    // Another member sees the edit too.
    const b = await device();
    await b.controller.sync();
    expect(b.store.get("team-token")).toBe("new");
  });

  it("are only pulled when the organization does not allow editing", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "read-only", value: "v", organization: org, edit: false });
    await a.controller.sync();
    a.store.set("read-only", "changed here");
    const r = await a.controller.sync();
    expect(r.pushed).toEqual([]);
    expect(r.errors).toEqual([]);
    expect(r.skipped).toContainEqual({ cipherId: c.id, reason: expect.stringMatching(/does not let you edit/) });
    expect(await remoteValue(c.id)).toBe("v");
    expect(a.store.get("read-only")).toBe("changed here");
    // Changes made in Bitwarden still arrive once the local edit is resolved.
    await server.editValue(c.id, "v2");
    expect((await a.controller.sync()).conflicts.map((x) => x.id)).toEqual(["read-only"]);
  });

  it("are skipped when the organization hides the password", async () => {
    const c = await server.addItem({ folder: "obsidian", name: "hidden", value: "v", organization: org, viewPassword: false });
    const r = await a.controller.sync();
    expect(a.store.get("hidden")).toBeNull();
    expect(r.skipped).toContainEqual({ cipherId: c.id, reason: expect.stringMatching(/hides/) });
  });

  it("never take over a personal secret with the same id, even when newer", async () => {
    await server.addItem({ folder: "obsidian", name: "api-key", value: "mine" });
    const theirs = await server.addItem({ folder: "obsidian", name: "api-key", value: "theirs", organization: org });
    const r = await a.controller.sync();
    expect(a.store.get("api-key")).toBe("mine");
    expect(r.skipped).toContainEqual({ cipherId: theirs.id, reason: expect.stringMatching(/personal item is used/) });
  });

  it("are skipped while the membership is not confirmed", async () => {
    const pending = await server.addOrganization({ key: null });
    const c = await server.addItem({ folder: "obsidian", name: "pending", value: "v", organization: pending });
    const r = await a.controller.sync();
    expect(a.store.get("pending")).toBeNull();
    expect(r.skipped).toContainEqual({ cipherId: c.id, reason: expect.stringMatching(/not available/) });
  });

  it("report an organization key that cannot be read, and personal items still sync", async () => {
    const broken = await server.addOrganization({ key: "4.AAAA" });
    await server.addItem({ folder: "obsidian", name: "personal", value: "p" });
    await server.addItem({ folder: "obsidian", name: "broken", value: "b", organization: broken });
    const r = await a.controller.sync();
    expect(a.store.get("personal")).toBe("p");
    expect(a.store.get("broken")).toBeNull();
    expect(r.errors).toEqual([expect.stringMatching(new RegExp(`organization ${broken}`))]);
  });

  it("are never where new uploads go", async () => {
    a.store.set("local-only", "x");
    a.controller.queueUpload("local-only", { kind: "global" });
    expect((await a.controller.sync()).created).toEqual(["local-only"]);
    expect(server.ciphers).toHaveLength(1);
    expect(server.ciphers[0]!.organizationId).toBeNull();
  });
});

describe("account private key", () => {
  it("refuses anything but RSA-OAEP organization keys", async () => {
    const userKey = await SymmetricKey.generate();
    const priv = await AccountPrivateKey.unwrap(await encryptBytes(new Uint8Array([1, 2, 3]), userKey), userKey);
    for (const bad of ["2.a|b|c", "5.AAAA|BBBB", "6.AAAA|BBBB", "AAAA", "4.!!!"]) {
      await expect(priv.decrypt(bad)).rejects.toBeInstanceOf(CryptoError);
    }
  });
});
