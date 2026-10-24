import { describe, expect, it } from "vitest";
import { BitwardenApi, encryptedUserKeyOf, resolveServerUrls } from "../src/bw/api";
import { unlockUserKey } from "../src/bw/vault";
import { FakeBitwardenServer, SERVER } from "./helpers/fakeServer";

describe("unlockUserKey", () => {
  it("salts the master key with the email unless given another salt", async () => {
    const server = await FakeBitwardenServer.create();
    const api = new BitwardenApi(resolveServerUrls(SERVER), server.http, { identifier: "dev", name: "test" });
    await api.loginWithApiKey(server.account);
    const encrypted = encryptedUserKeyOf(await api.sync())!;
    const { email, password } = server.account;
    const key = await unlockUserKey(api, email, password, encrypted);
    expect(key.exportBytes()).toEqual(server.account.userKey.exportBytes());
    await expect(unlockUserKey(api, email, password, encrypted, { salt: "other@example.com" })).rejects.toThrow(/MAC/);
  });
});
