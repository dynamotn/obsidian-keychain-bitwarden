// Where Argon2id runs. An account may ask for up to 1 GiB and 10 iterations;
// on a phone that can take long enough to freeze Obsidian if it runs on the
// main thread, so the plugin runs it in a Web Worker that can be stopped.

import { argon2id } from "hash-wasm";

export interface Argon2Input {
  password: Uint8Array<ArrayBuffer>;
  salt: Uint8Array<ArrayBuffer>;
  iterations: number;
  /** KiB, as Argon2 counts it. */
  memoryKiB: number;
  parallelism: number;
}

/** Derives a 32-byte Argon2id hash. Runners may wipe `input.password`; do not reuse it. */
export type Argon2Runner = (input: Argon2Input, signal?: AbortSignal) => Promise<Uint8Array<ArrayBuffer>>;

/** The derivation was stopped: the vault was locked or the unlock dialog closed. */
export class KdfAbortedError extends Error {
  override name = "KdfAbortedError";
  constructor() {
    super("Unlocking was cancelled");
  }
}

export class KdfTimeoutError extends Error {
  override name = "KdfTimeoutError";
  constructor(seconds: number) {
    super(
      `Deriving the key took longer than ${seconds} seconds and was stopped. ` +
        `The Argon2 settings of this Bitwarden account may be too heavy for this device.`,
    );
  }
}

/** Runs on the calling thread. Used by tests and when workers are unavailable; cannot be interrupted. */
export const argon2InThread: Argon2Runner = async (input, signal) => {
  if (signal?.aborted) throw new KdfAbortedError();
  const out = await argon2id({
    password: input.password,
    salt: input.salt,
    iterations: input.iterations,
    memorySize: input.memoryKiB,
    parallelism: input.parallelism,
    hashLength: 32,
    outputType: "binary",
  });
  if (signal?.aborted) {
    out.fill(0);
    throw new KdfAbortedError();
  }
  return new Uint8Array(out);
};

/** Too heavy to derive on the main thread, where nothing can stop it. */
export class KdfTooHeavyError extends Error {
  override name = "KdfTooHeavyError";
  constructor(memoryKiB: number, maxKiB: number) {
    super(
      `This device cannot derive the key in the background, and the account's Argon2 memory ` +
        `(${Math.round(memoryKiB / 1024)} MiB) would freeze Obsidian while it runs; at most ` +
        `${Math.round(maxKiB / 1024)} MiB is derived in the foreground. Lower the KDF memory in Bitwarden to unlock here.`,
    );
  }
}

/** Above this the main-thread fallback refuses: twice Bitwarden's default of 64 MiB. */
export const IN_THREAD_MAX_MEMORY_KIB = 128 * 1024;

/**
 * Like `argon2InThread`, for when no worker can run: a derivation on the main
 * thread can be neither aborted nor timed out, so a heavy one is refused
 * up front instead of freezing the app.
 */
export function argon2InThreadUpTo(maxMemoryKiB: number): Argon2Runner {
  return (input, signal) => {
    if (input.memoryKiB > maxMemoryKiB) {
      input.password.fill(0);
      return Promise.reject(new KdfTooHeavyError(input.memoryKiB, maxMemoryKiB));
    }
    return argon2InThread(input, signal);
  };
}

// --- Worker protocol ---------------------------------------------------------

export interface WorkerRequest {
  password: ArrayBuffer;
  salt: ArrayBuffer;
  iterations: number;
  memoryKiB: number;
  parallelism: number;
}

export type WorkerResponse = { key: ArrayBuffer } | { error: string };

/** The subset of the Worker API the runner needs, so tests can stand in for it. */
export interface WorkerLike {
  postMessage(message: WorkerRequest, transfer: Transferable[]): void;
  terminate(): void;
  onmessage: ((ev: MessageEvent<WorkerResponse>) => void) | null;
  onerror: ((ev: ErrorEvent) => void) | null;
}

export interface WorkerRunnerOptions {
  /** Starts a fresh worker for one derivation. */
  spawn: () => WorkerLike;
  /** Stops the derivation after this long. */
  timeoutMs: number;
  /** Used when a worker cannot be started at all (no Worker support, or blocked). */
  fallback?: Argon2Runner;
}

/** Runs each derivation in its own worker, terminated when done, aborted, or out of time. */
export function argon2InWorker({ spawn, timeoutMs, fallback }: WorkerRunnerOptions): Argon2Runner {
  return (input, signal) => {
    if (signal?.aborted) return Promise.reject(new KdfAbortedError());
    let worker: WorkerLike;
    try {
      worker = spawn();
    } catch (e) {
      if (fallback) return fallback(input, signal);
      return Promise.reject(e instanceof Error ? e : new Error(String(e)));
    }
    return new Promise<Uint8Array<ArrayBuffer>>((resolve, reject) => {
      let settled = false;
      const finish = (fn: () => void) => {
        if (settled) return;
        settled = true;
        window.clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        worker.terminate();
        fn();
      };
      const onAbort = () => finish(() => reject(new KdfAbortedError()));
      const timer = window.setTimeout(
        () => finish(() => reject(new KdfTimeoutError(Math.round(timeoutMs / 1000)))),
        timeoutMs,
      );
      signal?.addEventListener("abort", onAbort);
      worker.onmessage = (ev) => {
        const data = ev.data;
        finish(() => {
          if ("key" in data) resolve(new Uint8Array(data.key));
          else reject(new Error(`Key derivation failed: ${data.error}`));
        });
      };
      worker.onerror = (ev) => {
        ev.preventDefault();
        finish(() => reject(new Error(`Key derivation failed: ${ev.message || "the worker stopped"}`)));
      };
      // Hand the worker its own copy and transfer it, so no copy stays on this thread.
      const password = input.password.slice().buffer;
      input.password.fill(0);
      const salt = input.salt.slice().buffer;
      worker.postMessage(
        {
          password,
          salt,
          iterations: input.iterations,
          memoryKiB: input.memoryKiB,
          parallelism: input.parallelism,
        },
        [password, salt],
      );
    });
  };
}
