// Live updates from the Bitwarden notifications hub (SignalR over a
// WebSocket, MessagePack protocol), so a change made on another device is
// pulled within seconds instead of at the next poll.
//
// A notification is never trusted for content: it only says "something
// changed", and the regular sync then fetches and verifies everything. A
// hostile or noisy server can therefore at most cause extra syncs, which are
// coalesced and spaced out.

import { decodeMsgPack, splitSignalRFrames, type MsgMap, type MsgValue } from "./msgpack";

/** Bitwarden PushType values that mean the vault changed. */
const VAULT_CHANGES = new Set([
  0, // SyncCipherUpdate
  1, // SyncCipherCreate
  2, // SyncLoginDelete
  3, // SyncFolderDelete
  4, // SyncCiphers
  5, // SyncVault
  6, // SyncOrgKeys
  7, // SyncFolderCreate
  8, // SyncFolderUpdate
  9, // SyncCipherDelete
]);

const RECORD_SEPARATOR = "\u001e";
const HANDSHAKE = `{"protocol":"messagepack","version":1}${RECORD_SEPARATOR}`;
/** A SignalR ping message ([6]) with its length prefix. */
const PING: Uint8Array<ArrayBuffer> = new Uint8Array([0x02, 0x91, 0x06]);
const MessageType = { Invocation: 1, Ping: 6, Close: 7 } as const;

/** The subset of the WebSocket API the hub client needs, so tests can stand in for it. */
export interface SocketLike {
  binaryType: string;
  onopen: ((ev: Event) => void) | null;
  onmessage: ((ev: MessageEvent) => void) | null;
  onclose: ((ev: CloseEvent) => void) | null;
  onerror: ((ev: Event) => void) | null;
  send(data: string | Uint8Array<ArrayBuffer>): void;
  close(): void;
}

export interface Timers {
  set(fn: () => void, ms: number): number;
  clear(id: number): void;
}

const windowTimers: Timers = {
  set: (fn, ms) => window.setTimeout(fn, ms),
  clear: (id) => window.clearTimeout(id),
};

export interface HubOptions {
  /** The hub's WebSocket URL with a fresh access token. */
  url: () => Promise<string>;
  createSocket: (url: string) => SocketLike;
  /** This device's identifier: changes it made itself are not reported back to it. */
  deviceId: () => string;
  /** Called (coalesced) when the vault changed elsewhere. */
  onChange: () => void;
  onConnected?: (connected: boolean) => void;
  timers?: Timers;
  pingIntervalMs?: number;
  /** Reconnect when nothing at all arrived for this long. */
  serverTimeoutMs?: number;
  /** Wait for notifications to settle before reporting them. */
  settleMs?: number;
  /** Never report changes more often than this. */
  minIntervalMs?: number;
  /** Delays before reconnect attempts; the last one repeats. */
  backoffMs?: number[];
  /** The delays start over only once a connection stayed up this long. */
  stableMs?: number;
}

/** Hub URL of a Bitwarden server, from its notifications base URL. */
export function hubUrl(notificationsBase: string, accessToken: string): string {
  const base = notificationsBase.replace(/^http(s?):/, "ws$1:").replace(/\/+$/, "");
  return `${base}/hub?access_token=${encodeURIComponent(accessToken)}`;
}

export class NotificationHub {
  private socket: SocketLike | null = null;
  private running = false;
  private handshakeDone = false;
  private attempt = 0;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private idleTimer: number | null = null;
  private stableTimer: number | null = null;
  private settleTimer: number | null = null;
  private lastChange = -Infinity;
  /** Bumped on every (re)connect, so callbacks of an old socket do nothing. */
  private epoch = 0;
  private readonly timers: Timers;
  private readonly o: Required<Omit<HubOptions, "onConnected" | "timers">> & Pick<HubOptions, "onConnected">;

  constructor(options: HubOptions) {
    this.timers = options.timers ?? windowTimers;
    this.o = {
      pingIntervalMs: 15_000,
      serverTimeoutMs: 60_000,
      settleMs: 1_000,
      minIntervalMs: 5_000,
      backoffMs: [2_000, 5_000, 15_000, 60_000, 300_000],
      stableMs: 30_000,
      ...options,
    };
  }

  get connected(): boolean {
    return this.handshakeDone;
  }

  start(): void {
    if (this.running) return;
    this.running = true;
    this.attempt = 0;
    void this.connect();
  }

  stop(): void {
    this.running = false;
    this.teardown();
    for (const t of [this.reconnectTimer, this.settleTimer]) if (t !== null) this.timers.clear(t);
    this.reconnectTimer = this.settleTimer = null;
  }

  /** Reconnects at once if the connection is down (for example when the app comes back to the foreground). */
  wake(): void {
    if (!this.running || this.socket) return;
    if (this.reconnectTimer !== null) this.timers.clear(this.reconnectTimer);
    this.reconnectTimer = null;
    void this.connect();
  }

  private async connect(): Promise<void> {
    const epoch = ++this.epoch;
    let url: string;
    try {
      url = await this.o.url();
    } catch {
      if (epoch === this.epoch) this.scheduleReconnect();
      return;
    }
    if (!this.running || epoch !== this.epoch) return;
    let socket: SocketLike;
    try {
      socket = this.o.createSocket(url);
    } catch {
      this.scheduleReconnect();
      return;
    }
    this.socket = socket;
    socket.binaryType = "arraybuffer";
    const current = () => this.running && epoch === this.epoch;
    socket.onopen = () => {
      if (!current()) return;
      socket.send(HANDSHAKE);
      this.touch();
    };
    socket.onmessage = (ev) => {
      if (!current()) return;
      this.touch();
      try {
        this.receive(ev.data);
      } catch {
        // Malformed data: start over rather than guess.
        this.dropConnection();
      }
    };
    socket.onerror = () => {
      if (current()) this.dropConnection();
    };
    socket.onclose = () => {
      if (current()) this.dropConnection();
    };
  }

  private receive(data: unknown): void {
    if (!this.handshakeDone) {
      const text = typeof data === "string" ? data : new TextDecoder().decode(toBytes(data));
      const end = text.indexOf(RECORD_SEPARATOR);
      if (end < 0) throw new Error("Malformed handshake");
      const response = JSON.parse(text.slice(0, end)) as { error?: unknown };
      if (response.error) throw new Error("Handshake refused");
      this.handshakeDone = true;
      // Not yet: a server that accepts the handshake and then closes would get a reconnect every 2 s.
      this.stableTimer = this.timers.set(() => {
        this.stableTimer = null;
        this.attempt = 0;
      }, this.o.stableMs);
      this.o.onConnected?.(true);
      this.schedulePing();
      const rest = toBytes(data).subarray(new TextEncoder().encode(text.slice(0, end + 1)).length);
      if (rest.length) this.receive(rest);
      return;
    }
    if (typeof data === "string") return; // Only the MessagePack protocol was negotiated.
    for (const frame of splitSignalRFrames(toBytes(data))) this.handleMessage(decodeMsgPack(frame));
  }

  private handleMessage(message: MsgValue): void {
    if (!Array.isArray(message)) return;
    const type = message[0];
    if (type === MessageType.Close) {
      this.dropConnection();
      return;
    }
    if (type !== MessageType.Invocation || message[3] !== "ReceiveMessage") return;
    const args = message[4];
    const n = Array.isArray(args) ? args[0] : null;
    if (!n || typeof n !== "object" || Array.isArray(n) || n instanceof Uint8Array || n instanceof Date) return;
    const notification = n as MsgMap;
    if (!VAULT_CHANGES.has(notification.Type as number)) return;
    if (notification.ContextId === this.o.deviceId()) return;
    this.noteChange();
  }

  /** Coalesces a burst of notifications into one report, spaced at least minIntervalMs apart. */
  private noteChange(): void {
    if (this.settleTimer !== null) this.timers.clear(this.settleTimer);
    const now = Date.now();
    const wait = Math.max(this.o.settleMs, this.lastChange + this.o.minIntervalMs - now);
    this.settleTimer = this.timers.set(() => {
      this.settleTimer = null;
      this.lastChange = Date.now();
      // A callback queued before stop() cleared it must not start a sync.
      if (this.running) this.o.onChange();
    }, wait);
  }

  private schedulePing(): void {
    this.pingTimer = this.timers.set(() => {
      this.pingTimer = null;
      // A ping left over from an earlier socket must not reach one still handshaking.
      if (!this.socket || !this.handshakeDone) return;
      try {
        this.socket.send(PING);
      } catch {
        this.dropConnection();
        return;
      }
      this.schedulePing();
    }, this.o.pingIntervalMs);
  }

  /** Something arrived: the connection is alive. */
  private touch(): void {
    if (this.idleTimer !== null) this.timers.clear(this.idleTimer);
    this.idleTimer = this.timers.set(() => {
      this.idleTimer = null;
      this.dropConnection();
    }, this.o.serverTimeoutMs);
  }

  private dropConnection(): void {
    this.teardown();
    this.scheduleReconnect();
  }

  private teardown(): void {
    this.epoch++;
    const wasConnected = this.handshakeDone;
    this.handshakeDone = false;
    for (const t of [this.pingTimer, this.idleTimer, this.stableTimer]) if (t !== null) this.timers.clear(t);
    this.pingTimer = this.idleTimer = this.stableTimer = null;
    const socket = this.socket;
    this.socket = null;
    if (socket) {
      socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
      try {
        socket.close();
      } catch {
        // Already closed.
      }
    }
    if (wasConnected) this.o.onConnected?.(false);
  }

  private scheduleReconnect(): void {
    if (!this.running || this.reconnectTimer !== null) return;
    const delays = this.o.backoffMs;
    const delay = delays[Math.min(this.attempt, delays.length - 1)]!;
    this.attempt++;
    this.reconnectTimer = this.timers.set(() => {
      this.reconnectTimer = null;
      if (this.running) void this.connect();
    }, delay);
  }
}

function toBytes(data: unknown): Uint8Array {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === "string") return new TextEncoder().encode(data);
  throw new Error("Unexpected WebSocket message type");
}
