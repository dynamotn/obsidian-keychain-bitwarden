// The host ports dybw-core's WasmSession runs on, over Obsidian's APIs. They follow the core's Host contract
// (dybw-core crates/dybw-core-wasm/src/host.rs): a borrowed view into WASM memory is copied before the first await
// and that copy is wiped once used; a rejection is an Error whose message (all the core reads) is a fixed text that
// never includes a URL (the hub's carries the access token), a body or a secret.
import type { RequestUrlParam } from "obsidian";
import { KdfAbortedError, KdfTimeoutError, KdfTooHeavyError, type Argon2Runner } from "../bw/argon2";

/** Every request is bounded: the keys a running call holds outlive a `lock` until the request settles. */
export const HTTP_TIMEOUT_MS = 30_000;
/** What `http` rejects with when the request runs out of time. */
export const HTTP_TIMEOUT = "timeout";
export const HTTP_FAILED = "the request failed";
/** What `rsaOaepDecrypt` rejects with when the PKCS#8 key cannot be imported (the core's `RSA_KEY_ERROR`). */
export const RSA_KEY_ERROR = "key";
/** What `argon2id` rejects with when the unlock was cancelled. */
export const KDF_ABORTED = "aborted";
export const SOCKET_FAILED = "the connection failed";
export const SOCKET_CLOSED = "the connection is closed";
export const STORAGE_FAILED = "the device storage failed";

/** The plugin's localStorage keys: the core's `<key>` lives under `keychain-bitwarden:<key>`. */
export const STORAGE_PREFIX = "keychain-bitwarden:";
/** The device state the plugin has always kept; the core's `sync-state` is this very JSON object. */
export const STATE_KEY = `${STORAGE_PREFIX}state`;
const CORE_STATE = "sync-state";
const CORE_DEVICE = "device";
/** setTimeout's largest delay; a longer one fires at once. */
const MAX_TIMER_MS = 2 ** 31 - 1;
const WEBSOCKET_OPEN = 1;

export type SocketLike = Pick<
  WebSocket,
  "binaryType" | "readyState" | "onopen" | "onmessage" | "onerror" | "onclose" | "send" | "close"
>;

export interface PortDeps {
  requestUrl(request: RequestUrlParam): Promise<{ status: number; arrayBuffer: ArrayBuffer }>;
  loadLocalStorage(key: string): unknown;
  saveLocalStorage(key: string, data: unknown): void;
  secretStorage: { getSecret(id: string): string | null; setSecret(id: string, secret: string): void };
  createSocket(url: string): SocketLike;
  argon2: Argon2Runner;
  crypto: Crypto;
  /** The running unlock's signal: cancelling the unlock aborts its derivation. */
  kdfSignal?: () => AbortSignal | undefined;
  /** Aborted when the hub must stop: a running sleep then ends at once. */
  hubSignal?: () => AbortSignal | undefined;
}

type Frame = string | Uint8Array<ArrayBuffer>;

interface Waiter {
  promise: Promise<Frame | null>;
  resolve(frame: Frame | null): void;
  reject(error: Error): void;
}

interface Connection {
  ws: SocketLike;
  /** Frames not yet handed to a `socketRecv`. */
  frames: Frame[];
  /** The `socketRecv` that waits for the next frame. */
  waiter?: Waiter;
  ended?: "failed" | "closed";
}

const wipe = (...copies: (Uint8Array | undefined)[]) => copies.forEach((c) => c?.fill(0));
const encode = (text: string) => new TextEncoder().encode(text);

/** Runs a synchronous Obsidian call as a promise that rejects with `text`, never the call's own error. */
function attempt<T>(text: string, call: () => T): Promise<T> {
  try {
    return Promise.resolve(call());
  } catch {
    return Promise.reject(new Error(text));
  }
}

export type HostPorts = ReturnType<typeof hostPorts>;

export function hostPorts(deps: PortDeps) {
  const sockets = new Map<number, Connection>();
  let lastSocket = 0;

  const localKey = (key: string) => (key === CORE_STATE ? STATE_KEY : STORAGE_PREFIX + key);
  /** The id the plugin kept inside its state before the core: an upgraded device keeps its identity. */
  const stateDeviceId = () => {
    const state = deps.loadLocalStorage(STATE_KEY) as { deviceId?: unknown } | null;
    return typeof state?.deviceId === "string" && state.deviceId ? state.deviceId : null;
  };

  const ended = (conn: Connection, how: "failed" | "closed") => {
    conn.ended ??= how;
    if (conn.ended === "failed") conn.waiter?.reject(new Error(SOCKET_FAILED));
    else conn.waiter?.resolve(null);
    conn.waiter = undefined;
  };

  return {
    nowMs: () => Date.now(),
    /** Never rejects; ends early when the hub's signal aborts. */
    sleepMs: (ms: number) =>
      new Promise<void>((resolve) => {
        const signal = deps.hubSignal?.();
        const done = () => {
          window.clearTimeout(timer);
          signal?.removeEventListener("abort", done);
          resolve();
        };
        const timer = window.setTimeout(done, Math.min(ms, MAX_TIMER_MS));
        if (signal?.aborted) done();
        else signal?.addEventListener("abort", done);
      }),
    /** `requestUrl` follows redirects (ADR 0018): the core then sends credentials only to an acknowledged origin. */
    refusesRedirects: () => false,
    random: (len: number) => deps.crypto.getRandomValues(new Uint8Array(len)),

    async http(method: string, url: string, headers: string, body?: Uint8Array): Promise<[number, Uint8Array]> {
      const copy = body?.slice();
      let timer: number | undefined;
      try {
        const request = new Promise<[number, Uint8Array]>((resolve) => {
          const h = Object.fromEntries(JSON.parse(headers) as [string, string][]);
          resolve(
            deps
              .requestUrl({ url, method, headers: h, body: copy?.buffer, throw: false })
              .then((res) => [res.status, new Uint8Array(res.arrayBuffer)]),
          );
        }).catch(() => Promise.reject(new Error(HTTP_FAILED)));
        // requestUrl cannot be aborted: the request runs on, but the core's call settles.
        const timeout = new Promise<never>((_, reject) => {
          timer = window.setTimeout(() => reject(new Error(HTTP_TIMEOUT)), HTTP_TIMEOUT_MS);
        });
        return await Promise.race([request, timeout]);
      } finally {
        window.clearTimeout(timer);
        wipe(copy);
      }
    },

    storageLoad: (key: string) =>
      attempt(STORAGE_FAILED, (): Uint8Array | null => {
        const value: unknown = deps.loadLocalStorage(localKey(key));
        if (key === CORE_STATE) return value == null ? null : encode(JSON.stringify(value));
        if (typeof value === "string") return encode(value);
        const legacy = key === CORE_DEVICE ? stateDeviceId() : null;
        return legacy === null ? null : encode(legacy);
      }),
    storageSave: (key: string, value: Uint8Array) =>
      attempt(STORAGE_FAILED, () => {
        // Decoded at once, before any await: `value` is a view into WASM memory.
        const text = new TextDecoder("utf-8", { fatal: true }).decode(value);
        deps.saveLocalStorage(localKey(key), key === CORE_STATE ? (JSON.parse(text) as unknown) : text);
      }),
    storageRemove: (key: string) => attempt(STORAGE_FAILED, () => deps.saveLocalStorage(localKey(key), null)),

    /** An empty secret is a removed one: Obsidian's secret storage cannot delete. */
    secretLoad: (key: string) => attempt(STORAGE_FAILED, () => deps.secretStorage.getSecret(key) || null),
    secretSave: (key: string, value: string) =>
      attempt(STORAGE_FAILED, () => deps.secretStorage.setSecret(key, value)),
    secretRemove: (key: string) => attempt(STORAGE_FAILED, () => deps.secretStorage.setSecret(key, "")),

    async argon2id(password: Uint8Array, salt: Uint8Array, iterations: number, memoryKiB: number, parallelism: number) {
      const [pw, s] = [password.slice(), salt.slice()];
      try {
        return await deps.argon2({ password: pw, salt: s, iterations, memoryKiB, parallelism }, deps.kdfSignal?.());
      } catch (e) {
        if (e instanceof KdfAbortedError) throw new Error(KDF_ABORTED);
        // Their texts name only the limits, for the user.
        if (e instanceof KdfTimeoutError || e instanceof KdfTooHeavyError) throw new Error(e.message);
        throw new Error("argon2id failed");
      } finally {
        wipe(pw, s);
      }
    },

    async rsaOaepDecrypt(pkcs8: Uint8Array, hash: string, ciphertext: Uint8Array) {
      const [der, ct] = [pkcs8.slice(), ciphertext.slice()];
      try {
        let key: CryptoKey;
        try {
          key = await deps.crypto.subtle.importKey("pkcs8", der, { name: "RSA-OAEP", hash }, false, ["decrypt"]);
        } catch {
          throw new Error(RSA_KEY_ERROR);
        }
        try {
          return new Uint8Array(await deps.crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, ct));
        } catch {
          throw new Error("decryption failed");
        }
      } finally {
        wipe(der, ct);
      }
    },

    /** Resolves the socket's id once it is open. */
    socketOpen: (url: string) =>
      new Promise<number>((resolve, reject) => {
        let ws: SocketLike;
        try {
          ws = deps.createSocket(url);
        } catch {
          // The engine's text names the URL.
          reject(new Error(SOCKET_FAILED));
          return;
        }
        const id = ++lastSocket;
        const conn: Connection = { ws, frames: [] };
        let opened = false;
        sockets.set(id, conn);
        ws.binaryType = "arraybuffer";
        ws.onopen = () => {
          opened = true;
          resolve(id);
        };
        ws.onmessage = (ev: MessageEvent<string | ArrayBuffer>) => {
          const frame = typeof ev.data === "string" ? ev.data : new Uint8Array(ev.data);
          if (conn.waiter) conn.waiter.resolve(frame);
          else conn.frames.push(frame);
          conn.waiter = undefined;
        };
        const fail = (how: "failed" | "closed") => () => {
          ended(conn, how);
          // Before `onopen` the core never learns the id: forget it here.
          reject(new Error(SOCKET_FAILED));
          if (!opened) sockets.delete(id);
        };
        ws.onerror = fail("failed");
        ws.onclose = fail("closed");
      }),
    socketSend(id: number, frame: Frame): Promise<void> {
      const ws = sockets.get(id)?.ws;
      return attempt(SOCKET_CLOSED, () => {
        if (ws?.readyState !== WEBSOCKET_OPEN) throw new Error();
        ws.send(frame);
      });
    },
    /**
     * The next frame, `null` once closed. A frame leaves the queue only to resolve a promise, and a call made while
     * one waits gets that same promise: the core drops a `recv` its timer beat and asks again, losing nothing.
     * Invariant this relies on: a frame is gone from `frames` once its promise resolves, even if the core never
     * reads it. That is safe only because the core's hub polls `recv` before its timer (a biased select) and never
     * keeps two `recv`s alive at once; a core that raced several would lose the frames the losers resolved with.
     */
    socketRecv(id: number): Promise<Frame | null> {
      const conn = sockets.get(id);
      if (!conn) return Promise.resolve(null);
      if (conn.waiter) return conn.waiter.promise;
      const frame = conn.frames.shift();
      if (frame !== undefined) return Promise.resolve(frame);
      if (conn.ended === "failed") return Promise.reject(new Error(SOCKET_FAILED));
      if (conn.ended) return Promise.resolve(null);
      const waiter = {} as Waiter;
      waiter.promise = new Promise((resolve, reject) => Object.assign(waiter, { resolve, reject }));
      conn.waiter = waiter;
      return waiter.promise;
    },
    socketClose(id: number) {
      const conn = sockets.get(id);
      if (!conn) return;
      sockets.delete(id);
      conn.ws.onopen = conn.ws.onmessage = conn.ws.onerror = conn.ws.onclose = null;
      conn.ws.close();
      ended(conn, "closed");
    },
    log: (message: string) => console.warn("[keychain-bitwarden]", message),
  };
}
