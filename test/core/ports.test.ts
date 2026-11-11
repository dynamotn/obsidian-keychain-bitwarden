import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import type { RequestUrlParam } from "obsidian";
import { WasmSession } from "../../vendor/dybw-core/dybw_core_wasm.js";
import { KdfAbortedError, KdfTimeoutError, KdfTooHeavyError, type Argon2Input } from "../../src/bw/argon2";
import { coreLoader } from "../../src/core/load";
import {
  HTTP_FAILED,
  HTTP_TIMEOUT,
  HTTP_TIMEOUT_MS,
  hostPorts,
  KDF_ABORTED,
  LOCAL_CHANGED,
  LocalChangedError,
  RSA_KEY_ERROR,
  SOCKET_CLOSED,
  SOCKET_FAILED,
  STATE_KEY,
  STORAGE_FAILED,
  type PortDeps,
  type SocketLike,
} from "../../src/core/ports";

beforeAll(() => {
  // The ports use window timers, as Obsidian asks of plugins; Node has none.
  if (typeof window === "undefined") vi.stubGlobal("window", globalThis);
});
afterEach(() => vi.useRealTimers());

const bytes = (text: string) => new TextEncoder().encode(text);
const text = (b: Uint8Array | null) => (b ? new TextDecoder().decode(b) : null);

/** Stands in for a WebSocket: records what it was sent, fires events when told to. */
class FakeSocket implements SocketLike {
  binaryType: BinaryType = "blob";
  readyState: 0 | 1 | 2 | 3 = 0;
  onopen: SocketLike["onopen"] = null;
  onmessage: SocketLike["onmessage"] = null;
  onerror: SocketLike["onerror"] = null;
  onclose: SocketLike["onclose"] = null;
  sent: unknown[] = [];
  closed = false;
  send(data: unknown) {
    this.sent.push(data);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
  }
  open() {
    this.readyState = 1;
    this.onopen?.call(this as unknown as WebSocket, new Event("open"));
  }
  message(data: string | ArrayBuffer) {
    this.onmessage?.call(this as unknown as WebSocket, new MessageEvent("message", { data }));
  }
  error() {
    this.readyState = 3;
    this.onerror?.call(this as unknown as WebSocket, new Event("error"));
  }
  closeFromServer() {
    this.readyState = 3;
    this.onclose?.call(this as unknown as WebSocket, new Event("close") as CloseEvent);
  }
}

function setup(overrides: Partial<PortDeps> = {}) {
  const local = new Map<string, unknown>();
  const secrets = new Map<string, string>();
  const sockets: FakeSocket[] = [];
  const requests: RequestUrlParam[] = [];
  const deps: PortDeps = {
    requestUrl: async (req) => {
      requests.push(req);
      return { status: 200, arrayBuffer: bytes("ok").buffer };
    },
    // As Obsidian's: a saved value comes back as a copy, null clears it.
    loadLocalStorage: (key) => (local.has(key) ? structuredClone(local.get(key)) : null),
    saveLocalStorage: (key, data) => (data === null ? local.delete(key) : local.set(key, structuredClone(data))),
    secretStorage: {
      getSecret: (id) => secrets.get(id) ?? null,
      setSecret: (id, value) => void secrets.set(id, value),
    },
    createSocket: () => {
      const s = new FakeSocket();
      sockets.push(s);
      return s;
    },
    argon2: async () => new Uint8Array(32).fill(7),
    crypto: globalThis.crypto,
    ...overrides,
  };
  return { ports: hostPorts(deps), local, secrets, sockets, requests };
}

const TODAYS_STATE = {
  version: 1,
  deviceId: "5d0c1e9a-old-device",
  base: {},
  pendingCreates: [],
  pendingScopes: {},
};

describe("storage ports", () => {
  it("device_id_survives_the_upgrade: the core uses the device id of today's state", async () => {
    await coreLoader()();
    const { ports, local } = setup();
    local.set(STATE_KEY, TODAYS_STATE);
    const session = new WasmSession(ports, "obsidian");
    try {
      expect(await session.deviceId()).toBe(TODAYS_STATE.deviceId);
      // A reset (locked) rewrites the state and keeps the identity.
      await session.resetState();
      expect((local.get(STATE_KEY) as { deviceId: string }).deviceId).toBe(TODAYS_STATE.deviceId);
      expect(await session.deviceId()).toBe(TODAYS_STATE.deviceId);
    } finally {
      session.free();
    }
  });

  it("a new device gets an id from the core, saved under its own key", async () => {
    await coreLoader()();
    const { ports, local } = setup();
    const session = new WasmSession(ports, "obsidian");
    try {
      const id = await session.deviceId();
      expect(id).toMatch(/^[0-9a-f-]{36}$/);
      expect(local.get("keychain-bitwarden:device")).toBe(id);
      expect(await session.deviceId()).toBe(id);
    } finally {
      session.free();
    }
  });

  it("device: the core's own key wins over the state's id; no id anywhere is missing", async () => {
    const { ports, local } = setup();
    expect(await ports.storageLoad("device")).toBeNull();
    local.set(STATE_KEY, { ...TODAYS_STATE, deviceId: "" });
    expect(await ports.storageLoad("device")).toBeNull();
    local.set(STATE_KEY, TODAYS_STATE);
    expect(text(await ports.storageLoad("device"))).toBe(TODAYS_STATE.deviceId);
    await ports.storageSave("device", bytes("own"));
    expect(text(await ports.storageLoad("device"))).toBe("own");
  });

  it("sync-state is today's keychain-bitwarden:state object, as JSON", async () => {
    const { ports, local } = setup();
    expect(await ports.storageLoad("sync-state")).toBeNull();
    local.set(STATE_KEY, TODAYS_STATE);
    expect(JSON.parse(text(await ports.storageLoad("sync-state"))!)).toEqual(TODAYS_STATE);
    const next = { ...TODAYS_STATE, writtenMarks: ["AAAA"] };
    await ports.storageSave("sync-state", bytes(JSON.stringify(next)));
    expect(local.get(STATE_KEY)).toEqual(next);
    expect(local.has("keychain-bitwarden:sync-state")).toBe(false);
    await ports.storageRemove("sync-state");
    expect(local.has(STATE_KEY)).toBe(false);
  });

  it("other keys are text under keychain-bitwarden:<key>", async () => {
    const { ports, local } = setup();
    expect(await ports.storageLoad("kdf-pin")).toBeNull();
    await ports.storageSave("kdf-pin", bytes('{"kdf":0}'));
    expect(local.get("keychain-bitwarden:kdf-pin")).toBe('{"kdf":0}');
    expect(text(await ports.storageLoad("kdf-pin"))).toBe('{"kdf":0}');
    local.set("keychain-bitwarden:security-version", 3);
    expect(await ports.storageLoad("security-version")).toBeNull();
    await ports.storageRemove("kdf-pin");
    expect(local.has("keychain-bitwarden:kdf-pin")).toBe(false);
  });

  it("a failing or refused save rejects with a fixed text", async () => {
    const { ports } = setup({
      saveLocalStorage: () => {
        throw new Error("QuotaExceededError: secret-ish detail");
      },
      loadLocalStorage: () => {
        throw new Error("detail");
      },
    });
    await expect(ports.storageSave("kdf-pin", bytes("x"))).rejects.toThrow(new Error(STORAGE_FAILED));
    await expect(ports.storageLoad("kdf-pin")).rejects.toThrow(new Error(STORAGE_FAILED));
    await expect(ports.storageRemove("kdf-pin")).rejects.toThrow(new Error(STORAGE_FAILED));
    const ok = setup().ports;
    await expect(ok.storageSave("kdf-pin", new Uint8Array([0xff]))).rejects.toThrow(new Error(STORAGE_FAILED));
    await expect(ok.storageSave("sync-state", bytes("{not json"))).rejects.toThrow(new Error(STORAGE_FAILED));
  });
});

describe("secret ports", () => {
  it("load, save and remove over Obsidian's secret storage; removing writes an empty secret", async () => {
    const { ports, secrets } = setup();
    expect(await ports.secretLoad("k")).toBeNull();
    await ports.secretSave("k", "value");
    expect(secrets.get("k")).toBe("value");
    expect(await ports.secretLoad("k")).toBe("value");
    await ports.secretRemove("k");
    expect(secrets.get("k")).toBe("");
    expect(await ports.secretLoad("k")).toBeNull();
  });

  it("a throwing secret storage rejects with a fixed text", async () => {
    const { ports } = setup({
      secretStorage: {
        getSecret: () => {
          throw new Error("value");
        },
        setSecret: () => {
          throw new Error("value");
        },
      },
    });
    await expect(ports.secretLoad("k")).rejects.toThrow(new Error(STORAGE_FAILED));
    await expect(ports.secretSave("k", "v")).rejects.toThrow(new Error(STORAGE_FAILED));
    await expect(ports.secretRemove("k")).rejects.toThrow(new Error(STORAGE_FAILED));
  });

  it("a write the storage refuses as changed since the sync began rejects with local-changed", async () => {
    const { ports } = setup({
      secretStorage: {
        getSecret: () => null,
        setSecret: () => {
          throw new LocalChangedError();
        },
      },
    });
    await expect(ports.secretSave("k", "v")).rejects.toThrow(new Error(LOCAL_CHANGED));
  });
});

describe("http port", () => {
  it("sends through requestUrl without throwing on status, and answers [status, body]", async () => {
    let seen: Uint8Array | undefined;
    const { ports, requests } = setup({
      requestUrl: async (req) => {
        requests.push(req);
        seen = new Uint8Array((req.body as ArrayBuffer).slice(0));
        return { status: 404, arrayBuffer: bytes("nope").buffer };
      },
    });
    const body = bytes("secret body");
    const [status, answer] = await ports.http("POST", "https://x.test/a", '[["Content-Type","text/plain"]]', body);
    expect([status, text(answer)]).toEqual([404, "nope"]);
    const req = requests[0]!;
    expect(req).toMatchObject({ url: "https://x.test/a", method: "POST", headers: { "Content-Type": "text/plain" } });
    expect(req.throw).toBe(false);
    expect(text(seen!)).toBe("secret body");
    // The copy is wiped once the request settled; the caller's view is the core's to wipe.
    expect(new Uint8Array(req.body as ArrayBuffer).every((b) => b === 0)).toBe(true);
    expect(text(body)).toBe("secret body");
  });

  it("a request without a body sends none", async () => {
    const { ports, requests } = setup();
    await ports.http("GET", "https://x.test/", "[]");
    expect(requests[0]!.body).toBeUndefined();
  });

  it("a failing request rejects with a fixed text that never names the URL", async () => {
    const url = "wss://x.test/hub?access_token=SECRET";
    for (const requestUrl of [
      () => Promise.reject(new Error(`net::ERR at ${url}`)),
      () => {
        throw new Error(url);
      },
    ]) {
      const { ports } = setup({ requestUrl });
      await expect(ports.http("GET", url, "[]")).rejects.toThrow(new Error(HTTP_FAILED));
    }
  });

  it("a request still running after 30 s rejects with timeout, and its body copy is wiped", async () => {
    vi.useFakeTimers();
    let sent: ArrayBuffer | undefined;
    const { ports } = setup({
      requestUrl: (req) => {
        sent = req.body as ArrayBuffer;
        return new Promise(() => {});
      },
    });
    const call = ports.http("POST", "https://x.test/", "[]", bytes("pw"));
    const settled = expect(call).rejects.toThrow(new Error(HTTP_TIMEOUT));
    await vi.advanceTimersByTimeAsync(HTTP_TIMEOUT_MS - 1);
    expect(new Uint8Array(sent!).some((b) => b !== 0)).toBe(true);
    await vi.advanceTimersByTimeAsync(1);
    await settled;
    expect(new Uint8Array(sent!).every((b) => b === 0)).toBe(true);
  });

  it("an answer in time clears the timer", async () => {
    vi.useFakeTimers();
    const { ports } = setup();
    await ports.http("GET", "https://x.test/", "[]");
    expect(vi.getTimerCount()).toBe(0);
  });

  it("follows redirects: refusesRedirects answers false (ADR 0018)", () => {
    expect(setup().ports.refusesRedirects()).toBe(false);
  });
});

describe("clock and random ports", () => {
  it("nowMs is the wall clock; random answers len fresh bytes", () => {
    const { ports } = setup();
    const before = Date.now();
    expect(ports.nowMs()).toBeGreaterThanOrEqual(before);
    const r = ports.random(64);
    expect(r).toHaveLength(64);
    expect(r.some((b) => b !== 0)).toBe(true);
  });

  it("sleepMs resolves after its time", async () => {
    vi.useFakeTimers();
    const { ports } = setup();
    let done = false;
    void ports.sleepMs(1000).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(999);
    expect(done).toBe(false);
    await vi.advanceTimersByTimeAsync(1);
    expect(done).toBe(true);
  });

  it("sleepMs ends at once on the hub's stop signal, also one aborted before, and never rejects", async () => {
    vi.useFakeTimers();
    const stop = new AbortController();
    const { ports } = setup({ hubSignal: () => stop.signal });
    const sleeping = ports.sleepMs(60_000);
    stop.abort(new Error("stop"));
    await expect(sleeping).resolves.toBeUndefined();
    expect(vi.getTimerCount()).toBe(0);
    await expect(ports.sleepMs(60_000)).resolves.toBeUndefined();
    expect(vi.getTimerCount()).toBe(0);
  });

  it("sleepMs caps a wait longer than a timer can hold, instead of firing at once", async () => {
    vi.useFakeTimers();
    const { ports } = setup();
    let done = false;
    void ports.sleepMs(2 ** 32 - 1).then(() => (done = true));
    await vi.advanceTimersByTimeAsync(1000);
    expect(done).toBe(false);
  });
});

describe("argon2id port", () => {
  it("runs the injected runner on copies, with the unlock's signal, and wipes the copies", async () => {
    const unlock = new AbortController();
    let input: Argon2Input | undefined;
    let signal: AbortSignal | undefined;
    const { ports } = setup({
      kdfSignal: () => unlock.signal,
      argon2: async (i, s) => {
        input = i;
        signal = s;
        expect(text(i.password)).toBe("pw");
        return new Uint8Array(32).fill(9);
      },
    });
    const password = bytes("pw");
    const salt = new Uint8Array(32).fill(1);
    const key = await ports.argon2id(password, salt, 3, 65536, 4);
    expect(key).toEqual(new Uint8Array(32).fill(9));
    expect(input).toMatchObject({ iterations: 3, memoryKiB: 65536, parallelism: 4 });
    expect(signal).toBe(unlock.signal);
    expect(input!.password.every((b) => b === 0)).toBe(true);
    expect(input!.salt.every((b) => b === 0)).toBe(true);
    expect(text(password)).toBe("pw");
  });

  it("maps a cancelled unlock to aborted, the limits to their texts, anything else to a fixed text", async () => {
    const cases: [unknown, string][] = [
      [new KdfAbortedError(), KDF_ABORTED],
      [new KdfTimeoutError(120), new KdfTimeoutError(120).message],
      [new KdfTooHeavyError(1 << 20, 1 << 17), new KdfTooHeavyError(1 << 20, 1 << 17).message],
      [new Error("worker said pw"), "argon2id failed"],
    ];
    for (const [error, expected] of cases) {
      const { ports } = setup({ argon2: () => Promise.reject(error) });
      await expect(ports.argon2id(bytes("pw"), new Uint8Array(32), 1, 1024, 1)).rejects.toThrow(new Error(expected));
    }
  });
});

describe("rsaOaepDecrypt port", () => {
  it("decrypts with the PKCS#8 key; a bad key rejects key, a bad ciphertext a fixed text", async () => {
    const pair = await crypto.subtle.generateKey(
      { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
      true,
      ["encrypt", "decrypt"],
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, pair.publicKey, bytes("org key")));
    const { ports } = setup();
    expect(text(await ports.rsaOaepDecrypt(pkcs8, "SHA-1", ct))).toBe("org key");
    await expect(ports.rsaOaepDecrypt(new Uint8Array(8), "SHA-1", ct)).rejects.toThrow(new Error(RSA_KEY_ERROR));
    await expect(ports.rsaOaepDecrypt(pkcs8, "SHA-256", ct)).rejects.toThrow(new Error("decryption failed"));
  });
});

describe("socket ports", () => {
  async function opened() {
    const env = setup();
    const id = env.ports.socketOpen("wss://x.test/hub?access_token=SECRET");
    const socket = env.sockets[0]!;
    socket.open();
    return { ...env, id: await id, socket };
  }

  it("opens an arraybuffer socket and answers its id once open", async () => {
    const { id, socket } = await opened();
    expect(id).toBe(1);
    expect(socket.binaryType).toBe("arraybuffer");
  });

  it("a socket that fails or closes before it opens rejects with a fixed text", async () => {
    const { ports, sockets } = setup();
    const first = ports.socketOpen("wss://x.test/?access_token=SECRET");
    sockets[0]!.error();
    sockets[0]!.closeFromServer();
    await expect(first).rejects.toThrow(new Error(SOCKET_FAILED));
    const second = ports.socketOpen("wss://x.test/");
    sockets[1]!.closeFromServer();
    await expect(second).rejects.toThrow(new Error(SOCKET_FAILED));
    // Never opened: the ids are unknown, closed sockets.
    await expect(ports.socketRecv(1)).resolves.toBeNull();
    const throwing = setup({
      createSocket: (url) => {
        throw new SyntaxError(`bad ${url}`);
      },
    });
    await expect(throwing.ports.socketOpen("wss://x.test/?access_token=SECRET")).rejects.toThrow(new Error(SOCKET_FAILED));
  });

  it("queues frames in order, text and binary, until recv takes them", async () => {
    const { ports, id, socket } = await opened();
    socket.message("handshake\u001e");
    socket.message(new Uint8Array([1, 2]).buffer);
    expect(await ports.socketRecv(id)).toBe("handshake\u001e");
    expect(await ports.socketRecv(id)).toEqual(new Uint8Array([1, 2]));
    const waiting = ports.socketRecv(id);
    socket.message("later");
    expect(await waiting).toBe("later");
  });

  it("is cancel safe: a recv asked again while one waits shares its promise, so no frame is lost", async () => {
    const { ports, id, socket } = await opened();
    const dropped = ports.socketRecv(id);
    const again = ports.socketRecv(id);
    expect(again).toBe(dropped);
    socket.message("one");
    socket.message("two");
    expect(await again).toBe("one");
    expect(await ports.socketRecv(id)).toBe("two");
  });

  it("answers the queued frames, then null after the server closed", async () => {
    const { ports, id, socket } = await opened();
    const waiting = ports.socketRecv(id);
    socket.message("last");
    socket.closeFromServer();
    expect(await waiting).toBe("last");
    expect(await ports.socketRecv(id)).toBeNull();
    expect(await ports.socketRecv(id)).toBeNull();
  });

  it("a waiting recv ends with null on close, and with a fixed text on error", async () => {
    const a = await opened();
    const waiting = a.ports.socketRecv(a.id);
    a.socket.closeFromServer();
    expect(await waiting).toBeNull();
    const b = await opened();
    const failing = b.ports.socketRecv(b.id);
    b.socket.error();
    await expect(failing).rejects.toThrow(new Error(SOCKET_FAILED));
    b.socket.closeFromServer();
    await expect(b.ports.socketRecv(b.id)).rejects.toThrow(new Error(SOCKET_FAILED));
  });

  it("sends text and binary frames while open, refuses otherwise with a fixed text", async () => {
    const { ports, id, socket } = await opened();
    await ports.socketSend(id, "hello");
    await ports.socketSend(id, new Uint8Array([3]));
    expect(socket.sent).toEqual(["hello", new Uint8Array([3])]);
    await expect(ports.socketSend(99, "x")).rejects.toThrow(new Error(SOCKET_CLOSED));
    socket.send = () => {
      throw new Error("InvalidStateError");
    };
    await expect(ports.socketSend(id, "x")).rejects.toThrow(new Error(SOCKET_CLOSED));
    socket.readyState = 2;
    await expect(ports.socketSend(id, "x")).rejects.toThrow(new Error(SOCKET_CLOSED));
  });

  it("close closes the socket, ends a waiting recv with null and forgets the id", async () => {
    const { ports, id, socket } = await opened();
    const waiting = ports.socketRecv(id);
    ports.socketClose(id);
    expect(socket.closed).toBe(true);
    expect(socket.onmessage).toBeNull();
    expect(await waiting).toBeNull();
    expect(await ports.socketRecv(id)).toBeNull();
    ports.socketClose(id);
    await expect(ports.socketSend(id, "x")).rejects.toThrow(new Error(SOCKET_CLOSED));
  });
});

describe("log port", () => {
  it("writes to the console with the plugin's tag", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    setup().ports.log("dybw-core-wasm panicked at x.rs:1");
    expect(warn).toHaveBeenCalledWith("[keychain-bitwarden]", "dybw-core-wasm panicked at x.rs:1");
    warn.mockRestore();
  });
});
