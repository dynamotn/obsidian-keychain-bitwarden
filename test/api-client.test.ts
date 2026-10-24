import { beforeEach, describe, expect, it } from "vitest";
import { BitwardenApi, BitwardenApiError, encryptedUserKeyOf, resolveServerUrls, type CipherRequest } from "../src/bw/api";
import { KdfType } from "../src/bw/crypto";
import type { HttpRequest, HttpResponse } from "../src/bw/http";

const urls = resolveServerUrls("https://bw.example.org");
const device = { identifier: "dev-1", name: "Test device" };

/** Answers each request with the next queued response and records what was sent. */
function fakeHttp() {
  const sent: HttpRequest[] = [];
  const replies: HttpResponse[] = [];
  const http = async (req: HttpRequest): Promise<HttpResponse> => {
    sent.push(req);
    const reply = replies.shift();
    if (!reply) throw new Error(`unexpected request to ${req.url}`);
    return reply;
  };
  const reply = (status: number, body: unknown) =>
    replies.push({ status, text: typeof body === "string" ? body : JSON.stringify(body) });
  return { http, sent, reply };
}

const SYNC = { Profile: { Id: "user-1", Email: "a@b.c", Key: "2.uk" }, Folders: null, Ciphers: null };

const request: CipherRequest = {
  type: 2,
  folderId: null,
  organizationId: null,
  name: "2.name",
  notes: null,
  fields: [],
  favorite: false,
  reprompt: 0,
  key: null,
};

describe("BitwardenApi", () => {
  let now: number;
  let fake: ReturnType<typeof fakeHttp>;
  let api: BitwardenApi;

  beforeEach(() => {
    now = 1_000_000;
    fake = fakeHttp();
    api = new BitwardenApi(urls, fake.http, device, () => now);
  });

  async function login(expiresIn?: number) {
    fake.reply(200, { access_token: "tok", ...(expiresIn === undefined ? {} : { expires_in: expiresIn }) });
    await api.loginWithApiKey({ clientId: "user.x", clientSecret: "s" });
  }

  describe("prelogin", () => {
    it("reads PBKDF2 and Argon2id parameters", async () => {
      fake.reply(200, { Kdf: KdfType.PBKDF2, KdfIterations: 600_000 });
      expect(await api.prelogin("a@b.c")).toEqual({ type: KdfType.PBKDF2, iterations: 600_000 });
      fake.reply(200, { kdf: KdfType.Argon2id, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 });
      expect(await api.prelogin("a@b.c")).toEqual({ type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 4 });
      expect(fake.sent[0]).toMatchObject({ url: `${urls.identity}/accounts/prelogin`, body: '{"email":"a@b.c"}' });
    });

    it("leaves missing Argon2id parameters at zero, for key derivation to reject", async () => {
      fake.reply(200, { kdf: KdfType.Argon2id, kdfIterations: 3 });
      expect(await api.prelogin("a@b.c")).toEqual({ type: KdfType.Argon2id, iterations: 3, memory: 0, parallelism: 0 });
    });

    it("refuses a KDF it does not know", async () => {
      fake.reply(200, { kdf: 7, kdfIterations: 1 });
      await expect(api.prelogin("a@b.c")).rejects.toThrow("Unsupported KDF type from server: 7");
    });
  });

  describe("loginWithApiKey", () => {
    it("sends the client credentials and this device, then keeps the token", async () => {
      await login(7200);
      const body = new URLSearchParams(fake.sent[0]!.body);
      expect(body.get("grant_type")).toBe("client_credentials");
      expect(body.get("client_id")).toBe("user.x");
      expect(body.get("deviceIdentifier")).toBe("dev-1");
      expect(api.isLoggedIn).toBe(true);
      // Renewed a minute before the server's expiry.
      now += (7200 - 60) * 1000 - 1;
      expect(api.isLoggedIn).toBe(true);
      now += 1;
      expect(api.isLoggedIn).toBe(false);
    });

    it("assumes an hour when the server does not say how long the token lasts", async () => {
      await login();
      now += (3600 - 60) * 1000 - 1;
      expect(api.isLoggedIn).toBe(true);
      now += 1;
      expect(api.isLoggedIn).toBe(false);
    });

    it("refuses an answer without an access token", async () => {
      fake.reply(200, { token_type: "Bearer" });
      await expect(api.loginWithApiKey({ clientId: "user.x", clientSecret: "s" })).rejects.toThrow(
        "The server did not return an access token",
      );
      expect(api.isLoggedIn).toBe(false);
    });
  });

  describe("authenticated calls", () => {
    it("are refused before logging in, without reaching the server", async () => {
      await expect(api.sync()).rejects.toMatchObject({ status: 401, message: "Not logged in" });
      expect(() => api.notificationsHubUrl()).toThrow(BitwardenApiError);
      expect(fake.sent).toEqual([]);
    });

    it("are refused again once the token expired or after logging out", async () => {
      await login();
      expect(api.notificationsHubUrl()).toBe("wss://bw.example.org/notifications/hub?access_token=tok");
      now += 3600 * 1000;
      expect(() => api.notificationsHubUrl()).toThrow("Not logged in");
      await login();
      api.logout();
      await expect(api.trashItem("c1")).rejects.toThrow("Not logged in");
    });

    it("send the bearer token, and a JSON body only when there is one", async () => {
      await login();
      fake.reply(200, SYNC);
      await api.sync();
      fake.reply(200, "");
      await expect(api.trashItem("a/b")).resolves.toBeUndefined();
      const [, get, trash] = fake.sent;
      expect(get).toMatchObject({ method: "GET", url: `${urls.api}/sync?excludeDomains=true`, body: undefined });
      expect(get!.headers).toMatchObject({ Authorization: "Bearer tok", "Device-Type": "21" });
      expect(get!.headers).not.toHaveProperty("Content-Type");
      expect(trash).toMatchObject({ method: "PUT", url: `${urls.api}/ciphers/a%2Fb/delete`, body: undefined });
    });
  });

  describe("sync", () => {
    it("fills in missing lists and learns the account id for later writes", async () => {
      await login();
      fake.reply(200, SYNC);
      const sync = await api.sync();
      expect(sync.folders).toEqual([]);
      expect(sync.ciphers).toEqual([]);
      fake.reply(200, { Id: "c1" });
      await api.createItem(request);
      expect(JSON.parse(fake.sent.at(-1)!.body!)).toMatchObject({ name: "2.name", encryptedFor: "user-1" });
    });

    it.each([
      ["no profile", { Folders: [], Ciphers: [] }],
      ["no account key", { Profile: { Id: "user-1", Email: "a@b.c" }, Folders: [], Ciphers: [] }],
      ["an empty body", ""],
    ])("refuses a response with %s", async (_name, body) => {
      await login();
      fake.reply(200, body);
      await expect(api.sync()).rejects.toThrow("Sync response has no account key");
    });

    it("finds the account key where newer servers put it", () => {
      const sync = { profile: { id: "u", email: "e" }, folders: [], ciphers: [] };
      expect(encryptedUserKeyOf(sync)).toBeNull();
      expect(
        encryptedUserKeyOf({ ...sync, userDecryption: { masterPasswordUnlock: { masterKeyEncryptedUserKey: "2.k" } } }),
      ).toBe("2.k");
    });
  });

  it("refuses to write an item before a sync told it whose vault this is", async () => {
    await login();
    await expect(api.createItem(request)).rejects.toThrow("internal: sync before writing items");
    await expect(api.updateItem("c1", request)).rejects.toThrow("internal: sync before writing items");
    expect(fake.sent).toHaveLength(1);
  });

  describe("errors from the server", () => {
    it("quotes what the server says, marked as coming from it", async () => {
      fake.reply(400, { ErrorModel: { Message: "The cipher you are updating is out of date." } });
      const err = (await api.prelogin("a@b.c").catch((e: unknown) => e)) as BitwardenApiError;
      expect(err).toBeInstanceOf(BitwardenApiError);
      expect(err.message).toBe("HTTP 400 (server says: The cipher you are updating is out of date.)");
      expect(err.isOutOfDate).toBe(true);
    });

    it("joins several messages and collapses whitespace", async () => {
      fake.reply(400, { error_description: "bad\n\ncreds", message: "try\tagain", validationErrors: { a: ["b"] } });
      await expect(api.prelogin("a@b.c")).rejects.toThrow('HTTP 400 (server says: bad creds try again {"a":["b"]})');
    });

    it("clips long server text", async () => {
      fake.reply(500, { message: "x".repeat(500) });
      const err = (await api.prelogin("a@b.c").catch((e: unknown) => e)) as Error;
      expect(err.message).toBe(`HTTP 500 (server says: ${"x".repeat(200)}…)`);
    });

    it.each([
      ["a body that is not JSON", "<html>Bad gateway</html>"],
      ["an empty body", ""],
      ["JSON null", "null"],
      ["no text at all", { message: "", error_description: 42 }],
    ])("gives only the status for %s", async (_name, body) => {
      fake.reply(502, body);
      await expect(api.prelogin("a@b.c")).rejects.toThrow(/^HTTP 502$/);
    });
  });
});
