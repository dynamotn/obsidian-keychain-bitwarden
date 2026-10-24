// Performance budgets. Runs under Node and in WebKit/Chromium:
//   npm run perf            (Node)
//   npm run perf:browser    (WebKit + Chromium)
// Budgets are deliberately loose: they catch order-of-magnitude regressions,
// not noise. Timings are printed so they can be recorded in docs/.

import { describe, expect, it, type TaskMeta } from "vitest";
import { deriveMasterKey, encryptString, KdfType, SymmetricKey } from "../../src/bw/crypto";
import { readVault } from "../../src/bw/vault";
import type { CipherDto, SyncDto } from "../../src/bw/api";
import { planSync, type BaseEntry, type RemoteEntry } from "../../src/sync/plan";
import { FakeBitwardenServer } from "../helpers/fakeServer";
import { makeDevice } from "../helpers/device";

const engine = typeof navigator !== "undefined" && navigator.userAgent ? navigator.userAgent : "node";
const label = /AppleWebKit/.test(engine) && !/Chrome/.test(engine) ? "webkit" : /Chrome/.test(engine) ? "chromium" : "node";

declare module "vitest" {
  interface TaskMeta {
    perf?: string[];
  }
}

type Task = { readonly meta: TaskMeta };

async function time<T>(task: Task, name: string, fn: () => Promise<T> | T, budgetMs: number): Promise<T> {
  const t0 = performance.now();
  const out = await fn();
  const ms = performance.now() - t0;
  // Browser runs do not forward console output; task meta reaches the JSON reporter.
  const lines = task.meta.perf ?? [];
  lines.push(`[perf:${label}] ${name}: ${ms.toFixed(1)} ms (budget ${budgetMs} ms)`);
  task.meta.perf = lines;
  expect(ms).toBeLessThan(budgetMs);
  return out;
}

describe("performance", () => {
  it("PBKDF2-SHA256, 600,000 iterations (Bitwarden default)", async ({ task }) => {
    await time(task, "pbkdf2-600k", () => deriveMasterKey("pw", "a@b.c", { type: KdfType.PBKDF2, iterations: 600_000 }), 3_000);
  });

  it("Argon2id, 64 MiB / 3 iterations / 4 lanes (Bitwarden default)", async ({ task }) => {
    await time(
      task,
      "argon2id-64m-t3-p4",
      () => deriveMasterKey("pw", "a@b.c", { type: KdfType.Argon2id, iterations: 3, memory: 64, parallelism: 4 }),
      5_000,
    );
  });

  it("decrypts 1,000 marked secrets inside a 5,000-item vault", async ({ task }) => {
    const key = await SymmetricKey.generate();
    const value = await encryptString("sk-".padEnd(64, "x"), key);
    const name = await encryptString("secret-name", key);
    // Unmarked items still carry fields: their names must be decrypted to find the marker.
    const marked = [{ type: 0, name: await encryptString("obsidian:id", key), value: await encryptString("secret-name", key) }];
    const other = [{ type: 0, name: await encryptString("username", key), value: await encryptString("me", key) }];
    const ciphers: CipherDto[] = Array.from({ length: 5_000 }, (_, i) => ({
      id: `c${i}`,
      type: 2,
      folderId: null,
      organizationId: null,
      name,
      notes: value,
      fields: i < 1_000 ? marked : other,
      revisionDate: "2026-01-01T00:00:00Z",
    }));
    const sync: SyncDto = { profile: { id: "u", email: "e", key: "" }, folders: [], ciphers };
    const { records } = await time(task, "decrypt-1000-of-5000", () => readVault(sync, key), 3_000);
    expect(records).toHaveLength(1_000);
  });

  it("plans a 10,000-secret sync", async ({ task }) => {
    const remote = new Map<string, RemoteEntry>();
    const base = new Map<string, BaseEntry>();
    for (let i = 0; i < 10_000; i++) {
      const id = `secret-${i}`;
      remote.set(id, { id, cipherId: `c${i}`, revisionDate: i % 3 ? "2" : "1", fingerprint: `r${i % 5}` });
      base.set(id, { cipherId: `c${i}`, revisionDate: "1", fingerprint: "r0" });
    }
    const actions = await time(
      task,
      "plan-10000",
      () =>
        planSync({
          remote,
          base,
          local: (id) => ({ fingerprint: id.endsWith("7") ? "edited" : "r0" }),
          pendingCreates: new Set(),
          policy: "ask",
        }),
      500,
    );
    expect(actions.length).toBeGreaterThan(0);
  });

  it("first sync of 200 secrets end to end, then a no-op sync", async ({ task }) => {
    const server = await FakeBitwardenServer.create();
    for (let i = 0; i < 200; i++) await server.addItem({ name: `key-${i}`, value: `value-${i}` });
    const d = makeDevice(server.http, server.account);
    await d.controller.unlock(server.account.password);
    const first = await time(task, "first-sync-200", () => d.controller.sync(), 3_000);
    expect(first.pulled).toHaveLength(200);
    const again = await time(task, "noop-sync-200", () => d.controller.sync(), 2_000);
    expect(again.pulled).toHaveLength(0);
  });
});
