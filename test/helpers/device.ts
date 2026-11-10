// A plugin device for the tests: the controller on a real WasmSession, on the plugin's own host ports, with
// in-memory secret and local storage, and an HttpClient (the fake server, or fetch) behind Obsidian's requestUrl.
import type { RequestUrlParam } from "obsidian";
import { vi } from "vitest";
import { argon2InThread, type Argon2Runner } from "../../src/bw/argon2";
import {
  SECRET_API_ORIGIN,
  SecretsController,
  type ControllerSettings,
  type SecretStore,
} from "../../src/controller";
import { STATE_KEY, STORAGE_PREFIX, type SocketLike } from "../../src/core/ports";
import type { HttpClient, HttpRequest } from "./bw/http";

// The ports use window timers, as Obsidian asks of plugins; Node has none.
if (typeof window === "undefined") vi.stubGlobal("window", globalThis);

const ID_RULE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;

/** Mimics Obsidian's SecretStorage, including its id validation. */
export class MemorySecretStore implements SecretStore {
  readonly values = new Map<string, string>();
  get(id: string): string | null {
    return this.values.get(id) ?? null;
  }
  set(id: string, value: string): void {
    if (!ID_RULE.test(id)) throw new Error(`Invalid secret id: ${id}`);
    this.values.set(id, value);
  }
  list(): string[] {
    return [...this.values.keys()];
  }
}

/** The device state as the plugin keeps it in localStorage (data model §4). */
export interface DeviceState {
  version?: number;
  deviceId?: string;
  base: Record<string, { cipherId: string; revisionDate: string; fingerprint: string; scope?: string; pushConfirmed?: boolean }>;
  pendingCreates: string[];
  pendingScopes: Record<string, string>;
}

export interface TestDevice {
  controller: SecretsController;
  store: MemorySecretStore;
  settings: ControllerSettings;
  /** Obsidian's localStorage for this vault, by the plugin's keys. */
  localStorage: Map<string, unknown>;
  /** The saved device state; an empty one before the first save. */
  state(): DeviceState;
}

/** `http` as Obsidian's requestUrl: the plugin's http port runs on top of it, as in Obsidian. */
export function requestUrlOf(http: HttpClient) {
  return async (req: RequestUrlParam) => {
    const body = req.body instanceof ArrayBuffer && req.body.byteLength ? new TextDecoder().decode(req.body) : undefined;
    const res = await http({ url: req.url, method: req.method as HttpRequest["method"], headers: req.headers, body });
    return { status: res.status, arrayBuffer: new TextEncoder().encode(res.text).buffer };
  };
}

export function makeDevice(
  http: HttpClient,
  account: { email: string; clientId: string; clientSecret: string },
  opts: {
    vaultName?: string;
    serverUrl?: string;
    settings?: Partial<ControllerSettings>;
    argon2?: Argon2Runner;
    createSocket?: (url: string) => SocketLike;
    onTrap?: (message: string) => void;
  } = {},
): TestDevice {
  const serverUrl = opts.serverUrl ?? "https://bw.test";
  const store = new MemorySecretStore();
  const settings: ControllerSettings = {
    serverUrl,
    email: account.email,
    uploadFolder: "obsidian",
    conflictPolicy: "ask",
    rememberKey: false,
    syncOrganizations: false,
    ...opts.settings,
  };
  const localStorage = new Map<string, unknown>();
  const controller = new SecretsController({
    ports: {
      requestUrl: requestUrlOf(http),
      loadLocalStorage: (key) => (localStorage.has(key) ? structuredClone(localStorage.get(key)) : null),
      saveLocalStorage: (key, data) => (data === null ? localStorage.delete(key) : localStorage.set(key, structuredClone(data))),
      createSocket:
        opts.createSocket ??
        (() => {
          throw new Error("no hub here");
        }),
      argon2: opts.argon2 ?? argon2InThread,
      crypto: globalThis.crypto,
    },
    store,
    settings: () => settings,
    vaultName: opts.vaultName ?? "notes",
    deviceName: "test",
    onTrap: opts.onTrap,
  });
  controller.setApiKey("clientId", account.clientId);
  controller.setApiKey("clientSecret", account.clientSecret);
  // requestUrl follows redirects: a self-hosted server must be acknowledged on the device first (ADR 0018).
  localStorage.set(`${STORAGE_PREFIX}acknowledged-origins`, JSON.stringify([store.get(SECRET_API_ORIGIN)]));
  const state = () =>
    (localStorage.get(STATE_KEY) as DeviceState | undefined) ?? { base: {}, pendingCreates: [], pendingScopes: {} };
  return { controller, store, settings, localStorage, state };
}
