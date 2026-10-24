import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import vectors from "./fixtures/msgpack.json";
import { decodeMsgPack, MsgPackError, splitSignalRFrames, type MsgValue } from "../src/bw/msgpack";
import { hubUrl, NotificationHub, type SocketLike } from "../src/bw/notifications";
import { resolveServerUrls } from "../src/bw/api";

const hex = (s: string) => new Uint8Array(s.replace(/\s+/g, "").match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

/** Turns decoded values into the tagged JSON form gen_msgpack.py writes. */
function tagged(v: MsgValue): unknown {
  if (v instanceof Uint8Array) return { $bin: [...v].map((b) => b.toString(16).padStart(2, "0")).join("") };
  if (v instanceof Date) return { $date: v.getTime() };
  if (typeof v === "bigint") return { $big: v.toString() };
  if (Array.isArray(v)) return v.map(tagged);
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, tagged(x as MsgValue)]));
  return v;
}

// Bytes Vaultwarden 1.37.4 sent for a folder created by another session:
// [1, {}, nil, "ReceiveMessage", [{ContextId, Type: 7, Payload: {Id, UserId, RevisionDate}}]].
const VAULTWARDEN_FOLDER_CREATE = hex(`
  c1 01 95 01 80 c0 ae 52 65 63 65 69 76 65 4d 65 73 73 61 67 65 91 83 a9 43 6f 6e 74 65 78 74 49 64 d9 24 36
  37 38 33 30 64 30 33 2d 63 66 61 32 2d 34 31 61 33 2d 39 34 31 66 2d 61 38 35 31 36 30 65 66 33 39 65 38 a4
  54 79 70 65 07 a7 50 61 79 6c 6f 61 64 83 a2 49 64 d9 24 61 31 36 31 34 32 39 34 2d 37 30 63 66 2d 34 37 33
  63 2d 39 35 35 64 2d 63 32 63 30 36 61 38 31 62 64 31 33 a6 55 73 65 72 49 64 d9 24 36 32 64 35 39 62 64 30
  2d 62 66 36 36 2d 34 37 30 66 2d 61 63 35 62 2d 65 37 62 31 31 63 32 62 32 30 31 62 ac 52 65 76 69 73 69 6f
  6e 44 61 74 65 d7 ff 82 f3 ea 18 6a da cf 93`);
const VAULTWARDEN_CONTEXT = "67830d03-cfa2-41a3-941f-a85160ef39e8";

describe("MessagePack decoder (vectors from the Python msgpack library)", () => {
  for (const v of vectors) {
    it(v.name, () => {
      expect(tagged(decodeMsgPack(hex(v.hex)))).toEqual(v.expected);
    });
  }

  it("decodes a real Vaultwarden notification", () => {
    const [frame, ...rest] = splitSignalRFrames(VAULTWARDEN_FOLDER_CREATE);
    expect(rest).toEqual([]);
    const msg = decodeMsgPack(frame!) as MsgValue[];
    expect(msg.slice(0, 4)).toEqual([1, {}, null, "ReceiveMessage"]);
    const n = (msg[4] as MsgValue[])[0] as Record<string, MsgValue>;
    expect(n.ContextId).toBe(VAULTWARDEN_CONTEXT);
    expect(n.Type).toBe(7);
    expect((n.Payload as Record<string, MsgValue>).RevisionDate).toBeInstanceOf(Date);
  });

  it.each([
    ["truncated string", "a3 61 62"],
    ["truncated array", "92 01"],
    ["truncated uint32", "ce 00 01"],
    ["trailing bytes", "01 02"],
    ["reserved byte", "c1"],
    ["invalid UTF-8", "a2 c3 28"],
    ["huge declared array", "dd ff ff ff ff"],
    ["bad timestamp", "d5 ff 00 00"],
    ["array map key", "81 90 01"],
  ])("rejects %s", (_name, bytes) => {
    expect(() => decodeMsgPack(hex(bytes))).toThrow(MsgPackError);
  });

  it("rejects deep nesting instead of overflowing the stack", () => {
    expect(() => decodeMsgPack(new Uint8Array(1000).fill(0x91))).toThrow(/nested too deeply/);
  });

  it("does not let map keys reach the object prototype", () => {
    // {"__proto__": {"polluted": true}}
    const m = decodeMsgPack(hex("81 a9 5f 5f 70 72 6f 74 6f 5f 5f 81 a8 70 6f 6c 6c 75 74 65 64 c3")) as Record<string, unknown>;
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(m.__proto__).toEqual({ polluted: true });
  });
});

describe("SignalR framing", () => {
  it("splits several length-prefixed messages", () => {
    expect(splitSignalRFrames(hex("01 c0 02 91 06")).map((f) => [...f])).toEqual([[0xc0], [0x91, 0x06]]);
  });

  it("reads multi-byte lengths", () => {
    const body = new Uint8Array(300).fill(0xc0);
    const frames = splitSignalRFrames(new Uint8Array([0xac, 0x02, ...body]));
    expect(frames[0]!.length).toBe(300);
  });

  it.each([
    ["a truncated length", "80"],
    ["a truncated message", "05 c0"],
    ["an over-long length prefix", "ff ff ff ff ff 01"],
  ])("rejects %s", (_name, bytes) => {
    expect(() => splitSignalRFrames(hex(bytes))).toThrow(MsgPackError);
  });

  it("rejects oversized messages", () => {
    expect(() => splitSignalRFrames(new Uint8Array([0x80, 0x80, 0x80, 0x08]), 1024)).toThrow(/too large/);
  });
});

describe("hub URLs", () => {
  it.each([
    ["https://vault.bitwarden.com", "wss://notifications.bitwarden.com/hub?access_token=t%2Bk"],
    ["https://vault.bitwarden.eu", "wss://notifications.bitwarden.eu/hub?access_token=t%2Bk"],
    ["https://vault.example.com/bw/", "wss://vault.example.com/bw/notifications/hub?access_token=t%2Bk"],
    ["http://localhost:8080", "ws://localhost:8080/notifications/hub?access_token=t%2Bk"],
  ])("%s", (server, expected) => {
    expect(hubUrl(resolveServerUrls(server).notifications, "t+k")).toBe(expected);
  });
});

/** Stands in for a WebSocket and records what the client sends. */
class FakeSocket implements SocketLike {
  binaryType = "blob";
  onopen: SocketLike["onopen"] = null;
  onmessage: SocketLike["onmessage"] = null;
  onclose: SocketLike["onclose"] = null;
  onerror: SocketLike["onerror"] = null;
  sent: (string | Uint8Array)[] = [];
  closed = false;
  constructor(readonly url: string) {}
  send(data: string | Uint8Array): void {
    this.sent.push(data);
  }
  close(): void {
    this.closed = true;
  }
  open() {
    this.onopen?.(new Event("open"));
  }
  receive(data: string | Uint8Array) {
    this.onmessage?.({ data: data instanceof Uint8Array ? data.slice().buffer : data } as MessageEvent);
  }
  drop() {
    this.onclose?.({} as CloseEvent);
  }
}

/** Encodes a ReceiveMessage invocation the way the server frames it. */
function invocation(type: number, contextId: string | null): Uint8Array {
  const str = (s: string) => [0xa0 | s.length, ...new TextEncoder().encode(s)];
  const ctx = contextId === null ? [0xc0] : [0xd9, contextId.length, ...new TextEncoder().encode(contextId)];
  const body = [
    0x95, 0x01, 0x80, 0xc0, ...str("ReceiveMessage"),
    0x91, 0x83, ...str("ContextId"), ...ctx, ...str("Type"), type, ...str("Payload"), 0x80,
  ];
  if (body.length > 127) throw new Error("test helper only frames short messages");
  return new Uint8Array([body.length, ...body]);
}

describe("notifications hub client", () => {
  let sockets: FakeSocket[];
  let changes: number;
  let hub: NotificationHub;
  let url: () => Promise<string>;

  const timers = {
    set: (fn: () => void, ms: number) => setTimeout(fn, ms) as unknown as number,
    clear: (id: number) => clearTimeout(id),
  };

  const make = (opts: Partial<ConstructorParameters<typeof NotificationHub>[0]> = {}) =>
    new NotificationHub({
      url: () => url(),
      createSocket: (u) => {
        const s = new FakeSocket(u);
        sockets.push(s);
        return s;
      },
      deviceId: () => "this-device",
      onChange: () => changes++,
      timers,
      ...opts,
    });

  /** Lets the async connect() run up to creating the socket. */
  const flush = () => vi.advanceTimersByTimeAsync(0);

  async function connected(): Promise<FakeSocket> {
    await flush();
    const s = sockets.at(-1)!;
    s.open();
    s.receive(new Uint8Array([0x7b, 0x7d, 0x1e]));
    return s;
  }

  beforeEach(() => {
    vi.useFakeTimers();
    sockets = [];
    changes = 0;
    url = async () => "wss://bw.test/notifications/hub?access_token=tok";
    hub = make();
  });

  afterEach(() => {
    hub.stop();
    vi.useRealTimers();
  });

  it("negotiates MessagePack, then reports a change made elsewhere", async () => {
    hub.start();
    const s = await connected();
    expect(s.url).toBe("wss://bw.test/notifications/hub?access_token=tok");
    expect(s.sent[0]).toBe('{"protocol":"messagepack","version":1}\u001e');
    expect(hub.connected).toBe(true);
    s.receive(invocation(1, "other-device"));
    expect(changes).toBe(0);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("understands the frame Vaultwarden actually sends", async () => {
    hub.start();
    const s = await connected();
    s.receive(VAULTWARDEN_FOLDER_CREATE);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("accepts the handshake and a first message in one frame", async () => {
    hub.start();
    await flush();
    const s = sockets[0]!;
    s.open();
    s.receive(new Uint8Array([0x7b, 0x7d, 0x1e, ...invocation(0, "other-device")]));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("ignores changes this device made itself, and non-vault notifications", async () => {
    hub.start();
    const s = await connected();
    s.receive(invocation(0, "this-device"));
    s.receive(invocation(11, "other-device")); // LogOut
    s.receive(invocation(12, "other-device")); // SyncSendCreate
    await vi.advanceTimersByTimeAsync(10_000);
    expect(changes).toBe(0);
  });

  it("coalesces a burst and spaces reports out", async () => {
    hub.start();
    const s = await connected();
    for (let i = 0; i < 50; i++) s.receive(invocation(0, "other-device"));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
    s.receive(invocation(0, "other-device"));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
    await vi.advanceTimersByTimeAsync(4_000);
    expect(changes).toBe(2);
  });

  it("sends pings while connected", async () => {
    hub.start();
    const s = await connected();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(s.sent.slice(1).map((d) => [...(d as Uint8Array)])).toEqual([[0x02, 0x91, 0x06]]);
  });

  it("reconnects with growing delays after the connection drops", async () => {
    hub.start();
    const first = await connected();
    first.drop();
    expect(hub.connected).toBe(false);
    await vi.advanceTimersByTimeAsync(1_999);
    expect(sockets).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(sockets).toHaveLength(2);
    sockets[1]!.drop();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(sockets).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    expect(sockets).toHaveLength(3);
    // A connection that stayed up resets the delays.
    sockets[2]!.open();
    sockets[2]!.receive(new Uint8Array([0x7b, 0x7d, 0x1e]));
    await vi.advanceTimersByTimeAsync(30_000);
    sockets[2]!.drop();
    await vi.advanceTimersByTimeAsync(2_000);
    expect(sockets).toHaveLength(4);
  });

  it("keeps backing off from a server that accepts the handshake, then closes at once", async () => {
    hub.start();
    const delays: number[] = [];
    for (let i = 0; i < 4; i++) {
      const s = await connected();
      s.drop();
      const before = sockets.length;
      let waited = 0;
      while (sockets.length === before) {
        await vi.advanceTimersByTimeAsync(1_000);
        waited += 1_000;
      }
      delays.push(waited);
    }
    expect(delays).toEqual([2_000, 5_000, 15_000, 60_000]);
  });

  it("reconnects when the server goes silent", async () => {
    hub.start();
    await connected();
    await vi.advanceTimersByTimeAsync(60_000);
    expect(sockets[0]!.closed).toBe(true);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(sockets).toHaveLength(2);
  });

  it.each([
    ["a refused handshake", '{"error":"nope"}\u001e'],
    ["a malformed handshake", "garbage"],
  ])("starts over after %s", async (_name, reply) => {
    hub.start();
    await flush();
    sockets[0]!.open();
    sockets[0]!.receive(reply);
    expect(sockets[0]!.closed).toBe(true);
    expect(hub.connected).toBe(false);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(sockets).toHaveLength(2);
  });

  it("starts over after malformed MessagePack", async () => {
    hub.start();
    const s = await connected();
    s.receive(hex("03 92 01"));
    expect(s.closed).toBe(true);
  });

  it("starts over when the server sends Close", async () => {
    hub.start();
    const s = await connected();
    s.receive(hex("02 91 07"));
    expect(s.closed).toBe(true);
  });

  it("retries later when no URL can be had (for example while logging in fails)", async () => {
    let calls = 0;
    url = async () => {
      calls++;
      throw new Error("offline");
    };
    hub.start();
    await flush();
    expect(sockets).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(2_000);
    expect(calls).toBe(2);
  });

  it("stops for good: no reconnect and no late reports", async () => {
    hub.start();
    const s = await connected();
    s.receive(invocation(0, "other-device"));
    hub.stop();
    expect(s.closed).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(changes).toBe(0);
    expect(sockets).toHaveLength(1);
  });

  it("wakes up at once instead of waiting for the next attempt", async () => {
    hub.start();
    const s = await connected();
    s.drop();
    hub.wake();
    await flush();
    expect(sockets).toHaveLength(2);
  });

  it("ignores a stale socket's events after reconnecting", async () => {
    hub.start();
    const old = await connected();
    const staleOnMessage = old.onmessage;
    old.drop();
    await vi.advanceTimersByTimeAsync(2_000);
    await connected();
    staleOnMessage?.({ data: invocation(0, "other-device").slice().buffer } as MessageEvent);
    await vi.advanceTimersByTimeAsync(10_000);
    expect(changes).toBe(0);
  });
});
