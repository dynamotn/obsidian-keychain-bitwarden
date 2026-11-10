// The fake server as the core's `http` port: a real `WasmSession`, loaded as the plugin loads it and on the plugin's
// host ports, unlocks every kind of fake account and plans a pass over its items.
import { beforeAll, describe, expect, it, vi } from "vitest";
import { WasmSession } from "../../vendor/dybw-core/dybw_core_wasm.js";
import { argon2InThread } from "../../src/bw/argon2";
import { coreLoader } from "../../src/core/load";
import { hostPorts } from "../../src/core/ports";
import { KdfType, type KdfParams, type KeyAlgorithm } from "../helpers/bw/crypto";
import { FakeBitwardenServer, SERVER } from "../helpers/fakeServer";

beforeAll(async () => {
  // The ports use window timers, as Obsidian asks of plugins; Node has none.
  if (typeof window === "undefined") vi.stubGlobal("window", globalThis);
  await coreLoader()();
});

/** The plugin's ports on an empty device, with the fake server as `http`. */
function ports(server: FakeBitwardenServer) {
  const local = new Map<string, unknown>();
  const secrets = new Map<string, string>();
  const base = hostPorts({
    requestUrl: () => Promise.reject(new Error("the fake server is the http port")),
    loadLocalStorage: (key) => (local.has(key) ? structuredClone(local.get(key)) : null),
    saveLocalStorage: (key, data) => (data === null ? local.delete(key) : local.set(key, structuredClone(data))),
    secretStorage: { getSecret: (id) => secrets.get(id) ?? null, setSecret: (id, value) => void secrets.set(id, value) },
    createSocket: () => {
      throw new Error("no hub here");
    },
    argon2: argon2InThread,
    crypto: globalThis.crypto,
  });
  return { ...base, http: server.port };
}

/** The profile JSON as the core's README documents it. */
function profile(server: FakeBitwardenServer): string {
  return JSON.stringify({
    server: SERVER,
    email: server.account.email,
    deviceName: "test",
    deviceType: 8,
    clientName: "obsidian",
    clientVersion: "0",
    apiOrigin: SERVER,
    clientId: server.account.clientId,
  });
}

const PBKDF2: KdfParams = { type: KdfType.PBKDF2, iterations: 5000 };
const ARGON2ID: KdfParams = { type: KdfType.Argon2id, iterations: 2, memory: 16, parallelism: 1 };
const cases: [string, KdfParams, KeyAlgorithm, boolean][] = [
  ["a pbkdf2 account", PBKDF2, "aes256-cbc-hmac", false],
  ["an argon2id account", ARGON2ID, "aes256-cbc-hmac", false],
  ["a COSE xaes256gcm account", PBKDF2, "xaes256gcm", false],
  ["a COSE xchacha20poly1305 account", PBKDF2, "xchacha20poly1305", false],
  ["a COSE xaes256gcm account, newer sync shape", PBKDF2, "xaes256gcm", true],
  ["a COSE xchacha20poly1305 account, newer sync shape", PBKDF2, "xchacha20poly1305", true],
];

describe.each(cases)("%s", (_name, kdf, userKey, newSyncShape) => {
  it("unlocks a WasmSession through the fake server, and plans a pass over its items", async () => {
    const server = await FakeBitwardenServer.create(kdf, { userKey, newSyncShape });
    await server.addItem({ folder: "obsidian", name: "alpha", value: "remote value" });
    const session = new WasmSession(ports(server), "obsidian");
    // requestUrl follows redirects: a self-hosted origin is acknowledged first (ADR 0018).
    await session.acknowledgeOrigin(SERVER);

    const summary = JSON.parse(await session.unlock(profile(server), server.account.clientSecret, server.account.password));
    expect(summary).toMatchObject({ securityVersion: userKey === "aes256-cbc-hmac" ? 0 : 2, orgProblems: [] });

    const plan = JSON.parse(await session.planPass(JSON.stringify({ vaultName: "test" }), [], []));
    expect(plan).toEqual({ actions: [{ kind: "pull", id: "alpha" }], massClear: null });
    const sync = server.requests.find((r) => new URL(r.url).pathname === "/api/sync");
    expect(sync?.headers?.Authorization).toMatch(/^Bearer /);
    session.lock();
  });
});
