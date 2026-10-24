import { beforeAll, describe, expect, inject, it, vi } from "vitest";
import vectors from "./fixtures/vectors.json";
import {
  argon2InThread,
  argon2InWorker,
  KdfAbortedError,
  KdfTimeoutError,
  type Argon2Input,
  type WorkerLike,
  type WorkerRequest,
  type WorkerResponse,
} from "../src/bw/argon2";
import { deriveMasterKey, KdfType } from "../src/bw/crypto";
import { toBase64, utf8Encode } from "../src/bw/encoding";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice } from "./helpers/device";

beforeAll(() => {
  // The runner uses window timers, as Obsidian asks of plugins; Node has none.
  if (typeof window === "undefined") vi.stubGlobal("window", globalThis);
});

/** Stands in for a Worker: records what it was sent and answers when told to. */
class FakeWorker implements WorkerLike {
  onmessage: ((ev: MessageEvent<WorkerResponse>) => void) | null = null;
  onerror: ((ev: ErrorEvent) => void) | null = null;
  sent: WorkerRequest[] = [];
  terminated = false;
  postMessage(message: WorkerRequest): void {
    this.sent.push(message);
  }
  terminate(): void {
    this.terminated = true;
  }
  reply(data: WorkerResponse): void {
    this.onmessage?.({ data } as MessageEvent<WorkerResponse>);
  }
}

const input = (): Argon2Input => ({
  password: utf8Encode("hunter2"),
  salt: new Uint8Array(32).fill(7),
  iterations: 2,
  memoryKiB: 16 * 1024,
  parallelism: 1,
});

describe("Argon2 in a worker", () => {
  it("returns the worker's key and terminates it", async () => {
    const w = new FakeWorker();
    const run = argon2InWorker({ spawn: () => w, timeoutMs: 10_000 })(input());
    expect(w.sent).toHaveLength(1);
    w.reply({ key: new Uint8Array(32).fill(1).buffer });
    expect([...(await run)]).toEqual(new Array(32).fill(1));
    expect(w.terminated).toBe(true);
  });

  it("wipes the caller's copy of the password once it is handed over", async () => {
    const w = new FakeWorker();
    const i = input();
    const run = argon2InWorker({ spawn: () => w, timeoutMs: 10_000 })(i);
    expect(i.password.every((b) => b === 0)).toBe(true);
    expect(new TextDecoder().decode(w.sent[0]!.password)).toBe("hunter2");
    w.reply({ key: new ArrayBuffer(32) });
    await run;
  });

  it("stops the worker when aborted", async () => {
    const w = new FakeWorker();
    const abort = new AbortController();
    const run = argon2InWorker({ spawn: () => w, timeoutMs: 10_000 })(input(), abort.signal);
    abort.abort();
    await expect(run).rejects.toBeInstanceOf(KdfAbortedError);
    expect(w.terminated).toBe(true);
    // A late answer from the terminated worker changes nothing.
    w.reply({ key: new ArrayBuffer(32) });
  });

  it("does not start a worker when already aborted", async () => {
    const spawn = vi.fn(() => new FakeWorker());
    const abort = new AbortController();
    abort.abort();
    await expect(argon2InWorker({ spawn, timeoutMs: 10_000 })(input(), abort.signal)).rejects.toBeInstanceOf(
      KdfAbortedError,
    );
    expect(spawn).not.toHaveBeenCalled();
  });

  it("stops the worker when it runs out of time", async () => {
    const w = new FakeWorker();
    const run = argon2InWorker({ spawn: () => w, timeoutMs: 20 })(input());
    await expect(run).rejects.toBeInstanceOf(KdfTimeoutError);
    expect(w.terminated).toBe(true);
  });

  it("reports a failure inside the worker", async () => {
    const w = new FakeWorker();
    const run = argon2InWorker({ spawn: () => w, timeoutMs: 10_000 })(input());
    w.reply({ error: "out of memory" });
    await expect(run).rejects.toThrow(/out of memory/);
    expect(w.terminated).toBe(true);
  });

  it("falls back when a worker cannot be started", async () => {
    const fallback = vi.fn(async () => new Uint8Array(32).fill(9));
    const run = argon2InWorker({
      spawn: () => {
        throw new Error("blocked");
      },
      timeoutMs: 10_000,
      fallback,
    });
    expect([...(await run(input()))]).toEqual(new Array(32).fill(9));
    expect(fallback).toHaveBeenCalledOnce();
  });

  // Only browsers can start the real worker; WebKit and Chromium stand in for
  // Obsidian mobile here.
  it.runIf(typeof Worker !== "undefined")("derives the known-answer key in a real worker", async () => {
    const a = vectors.argon2id;
    const argon2 = argon2InWorker({
      spawn: () => new Worker(new URL("../src/bw/argon2.worker.ts", import.meta.url), { type: "module" }),
      timeoutMs: 60_000,
    });
    const mk = await deriveMasterKey(
      vectors.password,
      vectors.email,
      { type: KdfType.Argon2id, iterations: a.iterations, memory: a.memory, parallelism: a.parallelism },
      { argon2 },
    );
    expect(toBase64(mk)).toBe(a.masterKey);
  });

  it.runIf(typeof Worker !== "undefined")("derives the known-answer key in the embedded worker, as shipped", async () => {
    // The same build the plugin embeds in main.js, started the same way: a classic worker from a Blob URL.
    const url = URL.createObjectURL(new Blob([inject("argon2WorkerSource")], { type: "text/javascript" }));
    try {
      const a = vectors.argon2id;
      const mk = await deriveMasterKey(
        vectors.password,
        vectors.email,
        { type: KdfType.Argon2id, iterations: a.iterations, memory: a.memory, parallelism: a.parallelism },
        { argon2: argon2InWorker({ spawn: () => new Worker(url), timeoutMs: 60_000 }) },
      );
      expect(toBase64(mk)).toBe(a.masterKey);
    } finally {
      URL.revokeObjectURL(url);
    }
  });
});

describe("Argon2 on the calling thread", () => {
  it("refuses to start when already aborted", async () => {
    const abort = new AbortController();
    abort.abort();
    await expect(argon2InThread(input(), abort.signal)).rejects.toBeInstanceOf(KdfAbortedError);
  });
});

describe("unlocking with a cancellable derivation", () => {
  /** A runner that waits until it is aborted, like a slow phone. */
  const hanging = (started: () => void) => (_input: Argon2Input, signal?: AbortSignal) =>
    new Promise<Uint8Array<ArrayBuffer>>((_resolve, reject) => {
      started();
      signal?.addEventListener("abort", () => reject(new KdfAbortedError()));
    });

  const argonServer = () =>
    FakeBitwardenServer.create({ type: KdfType.Argon2id, iterations: 2, memory: 16, parallelism: 1 });

  it("stops deriving and stays locked when locked meanwhile", async () => {
    const server = await argonServer();
    let started!: () => void;
    const running = new Promise<void>((r) => (started = r));
    const d = makeDevice(server.http, server.account, { argon2: hanging(started) });
    const unlock = d.controller.unlock(server.account.password);
    await running;
    d.controller.lock();
    await expect(unlock).rejects.toBeInstanceOf(KdfAbortedError);
    expect(d.controller.isUnlocked).toBe(false);
  });

  it("stops deriving when the unlock is cancelled", async () => {
    const server = await argonServer();
    let started!: () => void;
    const running = new Promise<void>((r) => (started = r));
    const d = makeDevice(server.http, server.account, { argon2: hanging(started) });
    const unlock = d.controller.unlock(server.account.password);
    await running;
    d.controller.cancelUnlock();
    await expect(unlock).rejects.toBeInstanceOf(KdfAbortedError);
    expect(d.controller.isUnlocked).toBe(false);
  });

  it("does not unlock when locked after the key was derived", async () => {
    const server = await argonServer();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let d!: ReturnType<typeof makeDevice>;
    // Derives the real key, but lets the test lock before returning it.
    const lockedJustBefore = async (i: Argon2Input) => {
      const key = await argon2InThread(i);
      d.controller.lock();
      release();
      return key;
    };
    d = makeDevice(server.http, server.account, { argon2: lockedJustBefore });
    const unlock = d.controller.unlock(server.account.password);
    await gate;
    await expect(unlock).rejects.toBeInstanceOf(KdfAbortedError);
    expect(d.controller.isUnlocked).toBe(false);
  });
});
