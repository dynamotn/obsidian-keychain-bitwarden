import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { STATE_KEY, type SocketLike } from "../src/core/ports";
import type { HttpRequest } from "./helpers/bw/http";
import { FakeBitwardenServer } from "./helpers/fakeServer";
import { makeDevice, type TestDevice } from "./helpers/device";

// The plugin's live updates through the core's `runHub`, on the plugin's own socket port. The protocol itself
// (MessagePack, SignalR framing, timings, malformed frames) is tested in the core: docs/m6-test-map.md.

const HANDSHAKE = '{"protocol":"messagepack","version":1}\u001e';
const isVaultSync = (r: HttpRequest) => r.url.includes("/api/sync");
const hex = (s: string) => new Uint8Array(s.replace(/\s+/g, "").match(/../g)?.map((b) => parseInt(b, 16)) ?? []);

// Bytes Vaultwarden 1.37.4 sent for a folder created by another session.
const VAULTWARDEN_FOLDER_CREATE = hex(`
  c1 01 95 01 80 c0 ae 52 65 63 65 69 76 65 4d 65 73 73 61 67 65 91 83 a9 43 6f 6e 74 65 78 74 49 64 d9 24 36
  37 38 33 30 64 30 33 2d 63 66 61 32 2d 34 31 61 33 2d 39 34 31 66 2d 61 38 35 31 36 30 65 66 33 39 65 38 a4
  54 79 70 65 07 a7 50 61 79 6c 6f 61 64 83 a2 49 64 d9 24 61 31 36 31 34 32 39 34 2d 37 30 63 66 2d 34 37 33
  63 2d 39 35 35 64 2d 63 32 63 30 36 61 38 31 62 64 31 33 a6 55 73 65 72 49 64 d9 24 36 32 64 35 39 62 64 30
  2d 62 66 36 36 2d 34 37 30 66 2d 61 63 35 62 2d 65 37 62 31 31 63 32 62 32 30 31 62 ac 52 65 76 69 73 69 6f
  6e 44 61 74 65 d7 ff 82 f3 ea 18 6a da cf 93`);

/** A ReceiveMessage invocation framed as the server sends it. */
function invocation(type: number, contextId: string): Uint8Array {
  const str = (s: string) => [0xa0 | s.length, ...new TextEncoder().encode(s)];
  const body = [
    0x95, 0x01, 0x80, 0xc0, ...str("ReceiveMessage"),
    0x91, 0x83, ...str("ContextId"), 0xd9, contextId.length, ...new TextEncoder().encode(contextId),
    ...str("Type"), type, ...str("Payload"), 0x80,
  ];
  if (body.length > 127) throw new Error("test helper only frames short messages");
  return new Uint8Array([body.length, ...body]);
}

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
  constructor(readonly url: string) {}
  send(data: unknown) {
    this.sent.push(typeof data === "string" ? data : [...(data as Uint8Array)]);
  }
  close() {
    this.closed = true;
    this.readyState = 3;
  }
  open() {
    this.readyState = 1;
    this.onopen?.call(this as unknown as WebSocket, new Event("open"));
  }
  receive(data: Uint8Array) {
    this.onmessage?.call(this as unknown as WebSocket, new MessageEvent("message", { data: data.slice().buffer }));
  }
  error() {
    this.readyState = 3;
    this.onerror?.call(this as unknown as WebSocket, new Event("error"));
  }
  drop() {
    this.readyState = 3;
    this.onclose?.call(this as unknown as WebSocket, new Event("close") as CloseEvent);
  }
}

describe("notifications hub client", () => {
  let server: FakeBitwardenServer;
  let d: TestDevice;
  let sockets: FakeSocket[];
  let changes: number;
  let hub: Promise<void>;
  let failCreates: number;

  const start = () => (hub = d.controller.startHub(() => changes++));

  /** Waits for socket `n` (1-based), opens it and answers the handshake. */
  async function connected(n = sockets.length + 1): Promise<FakeSocket> {
    await vi.waitFor(() => expect(sockets).toHaveLength(n));
    const s = sockets[n - 1]!;
    s.open();
    await vi.waitFor(() => expect(s.sent[0]).toBe(HANDSHAKE));
    s.receive(new Uint8Array([0x7b, 0x7d, 0x1e]));
    return s;
  }

  async function makeUnlocked(before?: (device: TestDevice) => void) {
    d = makeDevice(server.http, server.account, {
      createSocket: (url) => {
        if (failCreates > 0 && failCreates--) throw new Error(`blocked ${url}`);
        const s = new FakeSocket(url);
        sockets.push(s);
        return s;
      },
    });
    before?.(d);
    await d.controller.unlock(server.account.password);
  }

  beforeEach(async () => {
    server = await FakeBitwardenServer.create();
    sockets = [];
    changes = 0;
    failCreates = 0;
    await makeUnlocked();
    // The ports sleep on window timers; the core reads the time from Date.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
  });

  afterEach(async () => {
    d.controller.stopHub();
    await hub;
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("negotiates MessagePack, then reports a change made elsewhere", async () => {
    start();
    const s = await connected();
    expect(s.url).toMatch(/^wss:\/\/bw\.test\/notifications\/hub\?access_token=./);
    expect(s.binaryType).toBe("arraybuffer");
    s.receive(invocation(1, "other-device"));
    await vi.advanceTimersByTimeAsync(999);
    expect(changes).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(changes).toBe(1);
  });

  it("understands the frame Vaultwarden actually sends", async () => {
    start();
    (await connected()).receive(VAULTWARDEN_FOLDER_CREATE);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("ignores changes this device made itself, and non-vault notifications", async () => {
    const own = await d.controller.deviceId();
    start();
    const s = await connected();
    s.receive(invocation(0, own));
    s.receive(invocation(11, "other-device")); // LogOut
    s.receive(invocation(12, "other-device")); // SyncSendCreate
    await vi.advanceTimersByTimeAsync(10_000);
    expect(changes).toBe(0);
  });

  it("ignores changes an upgraded device made itself, under the id it had before the core", async () => {
    const old = "5d0c1e9a-old-device";
    d.controller.lock();
    vi.useRealTimers();
    await makeUnlocked((device) =>
      device.localStorage.set(STATE_KEY, { version: 1, deviceId: old, base: {}, pendingCreates: [], pendingScopes: {} }),
    );
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "Date"] });
    expect(await d.controller.deviceId()).toBe(old);
    start();
    const s = await connected();
    s.receive(invocation(0, old));
    await vi.advanceTimersByTimeAsync(10_000);
    expect(changes).toBe(0);
    s.receive(invocation(0, "other-device"));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("coalesces a burst and spaces reports out", async () => {
    start();
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

  it("syncs once for a change pushed by another device", async () => {
    let syncs = 0;
    hub = d.controller.startHub(() => void d.controller.sync().then(() => syncs++));
    const s = await connected();
    await server.addItem({ name: "k", value: "v" });
    server.requests = [];
    for (let i = 0; i < 3; i++) s.receive(invocation(1, "other-device"));
    await vi.advanceTimersByTimeAsync(10_000);
    await vi.waitFor(() => expect(syncs).toBe(1));
    expect(server.requests.filter(isVaultSync)).toHaveLength(1);
    expect(d.store.get("k")).toBe("v");
  });

  it("sends pings while connected", async () => {
    start();
    const s = await connected();
    await vi.advanceTimersByTimeAsync(15_000);
    expect(s.sent.slice(1)).toEqual([[0x02, 0x91, 0x06]]);
  });

  it("reconnects with growing delays after the connection drops", async () => {
    start();
    (await connected()).drop();
    await vi.advanceTimersByTimeAsync(1_999);
    expect(sockets).toHaveLength(1);
    await vi.advanceTimersByTimeAsync(1);
    (await connected(2)).drop();
    await vi.advanceTimersByTimeAsync(4_999);
    expect(sockets).toHaveLength(2);
    await vi.advanceTimersByTimeAsync(1);
    await connected(3);
  });

  it("starts over after a socket error", async () => {
    start();
    const s = await connected();
    s.error();
    await vi.advanceTimersByTimeAsync(2_000);
    await connected(2);
    expect(s.closed).toBe(true);
  });

  it("retries later when the socket cannot be created", async () => {
    failCreates = 1;
    start();
    await vi.advanceTimersByTimeAsync(0);
    expect(sockets).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(2_000);
    await connected(1);
  });

  it("stops for good: no reconnect and no late reports", async () => {
    start();
    const s = await connected();
    s.receive(invocation(0, "other-device"));
    d.controller.stopHub();
    await hub;
    expect(s.closed).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(changes).toBe(0);
    expect(sockets).toHaveLength(1);
  });

  it("stops when locked, and never reconnects with the old token", async () => {
    start();
    const s = await connected();
    s.receive(invocation(0, "other-device"));
    d.controller.lock();
    await hub;
    expect(s.closed).toBe(true);
    await vi.advanceTimersByTimeAsync(600_000);
    expect(changes).toBe(0);
    expect(sockets).toHaveLength(1);
    await expect(d.controller.startHub(() => changes++)).resolves.toBeUndefined();
    expect(sockets).toHaveLength(1);
  });

  it("keeps its connection when started again", async () => {
    start();
    const s = await connected();
    await d.controller.startHub(() => changes++);
    await vi.advanceTimersByTimeAsync(0);
    expect(sockets).toHaveLength(1);
    expect(s.closed).toBe(false);
  });

  it("wakes up at once instead of waiting for the next attempt", async () => {
    start();
    (await connected()).drop();
    await vi.advanceTimersByTimeAsync(0);
    d.controller.wake();
    const s = await connected(2);
    s.receive(invocation(0, "other-device"));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("starts a connection that looks up over when woken", async () => {
    start();
    const first = await connected();
    d.controller.wake();
    await connected(2);
    await vi.waitFor(() => expect(first.closed).toBe(true));
    await vi.advanceTimersByTimeAsync(30_000);
    expect(sockets).toHaveLength(2);
  });

  it("keeps one connection when woken twice in a row", async () => {
    start();
    const first = await connected();
    d.controller.wake();
    d.controller.wake();
    const s = await connected(2);
    await vi.advanceTimersByTimeAsync(30_000);
    expect(sockets).toEqual([first, s]);
    expect(first.closed).toBe(true);
    expect(s.closed).toBe(false);
    s.receive(invocation(0, "other-device"));
    await vi.advanceTimersByTimeAsync(1_000);
    expect(changes).toBe(1);
  });

  it("stays stopped when locked right after a wake", async () => {
    start();
    const first = await connected();
    d.controller.wake();
    d.controller.lock();
    await vi.advanceTimersByTimeAsync(600_000);
    expect(first.closed).toBe(true);
    expect(sockets.every((x) => x.closed)).toBe(true);
    expect(changes).toBe(0);
  });

  it("does not wake a hub that was stopped", async () => {
    start();
    await connected();
    d.controller.stopHub();
    await hub;
    d.controller.wake();
    await vi.advanceTimersByTimeAsync(10_000);
    expect(sockets).toHaveLength(1);
  });
});
