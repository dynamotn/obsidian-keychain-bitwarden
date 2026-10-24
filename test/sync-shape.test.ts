// Newer Bitwarden servers move the account keys: the user key and the master
// key's salt into `userDecryption.masterPasswordUnlock`, the private key into
// `profile.accountKeys`. The plugin reads both shapes.

import { describe, expect, it } from "vitest";
import { ACCOUNT_KINDS, FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice } from "./helpers/device";

describe.each(ACCOUNT_KINDS)("the newer sync response, %s account key", (userKey) => {
  it("unlocks and syncs with the keys where newer servers put them", async () => {
    const server = await FakeBitwardenServer.create(undefined, { userKey, newSyncShape: true });
    await server.addItem({ name: "token", value: "t", itemKey: true });
    const d = makeDevice(server.http, server.account);
    await d.controller.unlock(server.account.password);
    expect((await d.controller.sync()).pulled).toEqual(["token"]);
  });

  it("uses the master key salt the server gives, not the email", async () => {
    const server = await FakeBitwardenServer.create(undefined, { userKey, newSyncShape: true, salt: "Old@Example.com " });
    const d = makeDevice(server.http, server.account);
    await d.controller.unlock(server.account.password);
    expect(d.controller.isUnlocked).toBe(true);
  });

  it("reads the private key from accountKeys, for organizations and the remembered key", async () => {
    const server = await FakeBitwardenServer.create(undefined, { userKey, newSyncShape: true });
    const org = await server.addOrganization();
    await server.addItem({ name: "team", value: "v", organization: org });
    const d = makeDevice(server.http, server.account, { settings: { syncOrganizations: true, rememberKey: true } });
    await d.controller.unlock(server.account.password);
    expect((await d.controller.sync()).pulled).toEqual(["team"]);
    d.controller.lock();
    expect(await d.controller.unlockFromRememberedKey()).toBe(true);
  });
});
