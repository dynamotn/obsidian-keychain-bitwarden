// Performance budgets. Runs under Node and in WebKit/Chromium:
//   npm run perf            (Node)
//   npm run perf:browser    (WebKit + Chromium)
// Budgets are deliberately loose: they catch order-of-magnitude regressions,
// not noise. Timings are printed so they can be recorded in docs/.

// plan-10000 (the planner alone) moved to dybw-core's `runPerf`, with the same budget (docs/m6-test-map.md).

import { describe, expect, it, type TaskMeta } from "vitest";
import { argon2InThread } from "../../src/bw/argon2";
import { coreLoader } from "../../src/core/load";
import { encryptString, KdfType } from "../helpers/bw/crypto";
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
  it("loads the dybw-core module: base64 decode, compile, instantiate (information, no budget)", async ({ task }) => {
    const t0 = performance.now();
    await coreLoader()();
    const ms = performance.now() - t0;
    task.meta.perf = [...(task.meta.perf ?? []), `[perf:${label}] core-load: ${ms.toFixed(1)} ms (information)`];
  });

  it("PBKDF2-SHA256, 600,000 iterations (Bitwarden default), as an unlock in the core", async ({ task }) => {
    const server = await FakeBitwardenServer.create({ type: KdfType.PBKDF2, iterations: 600_000 });
    const d = makeDevice(server.http, server.account);
    await time(task, "pbkdf2-600k", () => d.controller.unlock(server.account.password), 3_000);
  });

  it("Argon2id, 64 MiB / 3 iterations / 4 lanes (Bitwarden default)", async ({ task }) => {
    const input = { password: new Uint8Array(8), salt: new Uint8Array(32), iterations: 3, memoryKiB: 64 * 1024, parallelism: 4 };
    await time(task, "argon2id-64m-t3-p4", () => argon2InThread(input), 5_000);
  });

  it("decrypts 1,000 marked secrets inside a 5,000-item vault, as a first sync", async ({ task }) => {
    const server = await FakeBitwardenServer.create();
    const key = server.account.userKey;
    const value = await encryptString("sk-".padEnd(64, "x"), key);
    const name = await encryptString("secret-name", key);
    const marker = await encryptString("obsidian:id", key);
    // Unmarked items still carry fields: their names must be decrypted to find the marker.
    const other = [{ type: 0, name: await encryptString("username", key), value: await encryptString("me", key) }];
    for (let i = 0; i < 5_000; i++) {
      server.ciphers.push({
        id: `c${i}`,
        type: 2,
        folderId: null,
        organizationId: null,
        name,
        notes: value,
        fields: i < 1_000 ? [{ type: 0, name: marker, value: await encryptString(`secret-${i}`, key) }] : other,
        secureNote: { type: 0 },
        revisionDate: "2026-01-01T00:00:00Z",
      });
    }
    const d = makeDevice(server.http, server.account);
    await d.controller.unlock(server.account.password);
    const report = await time(task, "decrypt-1000-of-5000", () => d.controller.sync(), 3_000);
    expect(report.pulled).toHaveLength(1_000);
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
